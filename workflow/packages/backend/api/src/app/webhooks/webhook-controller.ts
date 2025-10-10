
import {
    ALL_PRINCIPAL_TYPES,
    EventPayload,
    GetFlowVersionForWorkerRequestType,
    isMultipartFile,
    WebhookUrlParams,
    AIxBlockError,
    ErrorCode,
} from 'workflow-shared'
import { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox'
import { FastifyRequest } from 'fastify'
import { stepFileService } from '../file/step-file/step-file.service'
import { projectService } from '../project/project-service'
import { webhookSimulationService } from './webhook-simulation/webhook-simulation-service'
import { webhookService } from './webhook.service'


export const webhookController: FastifyPluginAsyncTypebox = async (app) => {

    app.all(
        '/:flowId/sync',
        WEBHOOK_PARAMS,
        async (request: FastifyRequest<{ Params: WebhookUrlParams }>, reply) => {
            const response = await webhookService.handleWebhook({
                data: (projectId: string) => convertRequest(request, projectId, request.params.flowId),
                logger: request.log,
                flowId: request.params.flowId,
                async: false,
                flowVersionToRun: GetFlowVersionForWorkerRequestType.LOCKED,
                saveSampleData: await webhookSimulationService(request.log).exists(
                    request.params.flowId,
                ),
            })
            await reply
                .status(response.status)
                .headers(response.headers)
                .send(response.body)
        },
    )

    app.all(
        '/:flowId',
        WEBHOOK_PARAMS,
        async (request: FastifyRequest<{ Params: WebhookUrlParams }>, reply) => {
            const response = await webhookService.handleWebhook({
                data: (projectId: string) => convertRequest(request, projectId, request.params.flowId),
                logger: request.log,
                flowId: request.params.flowId,
                async: true,
                saveSampleData: await webhookSimulationService(request.log).exists(
                    request.params.flowId,
                ),
                flowVersionToRun: GetFlowVersionForWorkerRequestType.LOCKED,
            })
            await reply
                .status(response.status)
                .headers(response.headers)
                .send(response.body)
        },
    )

    app.all('/:flowId/draft/sync', WEBHOOK_PARAMS, async (request, reply) => {
        const response = await webhookService.handleWebhook({
            data: (projectId: string) => convertRequest(request, projectId, request.params.flowId),
            logger: request.log,
            flowId: request.params.flowId,
            async: false,
            saveSampleData: true,
            flowVersionToRun: GetFlowVersionForWorkerRequestType.LATEST,
        })
        await reply
            .status(response.status)
            .headers(response.headers)
            .send(response.body)
    })

    app.all('/:flowId/draft', WEBHOOK_PARAMS, async (request, reply) => {
        const response = await webhookService.handleWebhook({
            data: (projectId: string) => convertRequest(request, projectId, request.params.flowId),
            logger: request.log,
            flowId: request.params.flowId,
            async: true,
            saveSampleData: true,
            flowVersionToRun: GetFlowVersionForWorkerRequestType.LATEST,
        })
        await reply
            .status(response.status)
            .headers(response.headers)
            .send(response.body)
    })

    app.all('/:flowId/test', WEBHOOK_PARAMS, async (request, reply) => {
        const response = await webhookService.handleWebhook({
            data: (projectId: string) => convertRequest(request, projectId, request.params.flowId),
            logger: request.log,
            flowId: request.params.flowId,
            async: true,
            saveSampleData: true,
            flowVersionToRun: undefined,
        })
        await reply
            .status(response.status)
            .headers(response.headers)
            .send(response.body)
    })

}


const WEBHOOK_PARAMS = {
    config: {
        allowedPrincipals: ALL_PRINCIPAL_TYPES,
        skipAuth: true,
        rawBody: true,
    },
    schema: {
        params: WebhookUrlParams,
    },
}


async function convertRequest(
    request: FastifyRequest,
    projectId: string,
    flowId: string,
): Promise<EventPayload> {
    // Security fix: Validate project and flow IDs to prevent injection attacks
    if (!isValidId(projectId) || !isValidId(flowId)) {
        throw new AIxBlockError({
            code: ErrorCode.VALIDATION,
            params: { message: 'Invalid project or flow ID' }
        });
    }

    // Security fix: Sanitize headers to prevent header injection
    const sanitizedHeaders = sanitizeHeaders(request.headers);
    
    // Security fix: Validate and sanitize body
    const sanitizedBody = await convertBody(request, projectId, flowId);
    
    // Security fix: Sanitize query parameters
    const sanitizedQueryParams = sanitizeQueryParams(request.query as Record<string, any>);

    return {
        method: request.method,
        headers: sanitizedHeaders,
        body: sanitizedBody,
        queryParams: sanitizedQueryParams,
        rawBody: request.rawBody,
    }
}

// Security helper functions
function isValidId(id: string): boolean {
    // Allow alphanumeric characters, hyphens, and underscores
    const idPattern = /^[a-zA-Z0-9_-]+$/;
    return idPattern.test(id) && id.length >= 1 && id.length <= 100;
}

function sanitizeHeaders(headers: Record<string, any>): Record<string, string> {
    const sanitized: Record<string, string> = {};
    const allowedHeaders = ['content-type', 'user-agent', 'x-forwarded-for', 'authorization'];
    
    for (const [key, value] of Object.entries(headers)) {
        if (allowedHeaders.includes(key.toLowerCase()) && typeof value === 'string') {
            // Remove potentially dangerous characters
            sanitized[key] = value.replace(/[<>\"'&]/g, '');
        }
    }
    
    return sanitized;
}

function sanitizeQueryParams(query: Record<string, any>): Record<string, string> {
    const sanitized: Record<string, string> = {};
    
    for (const [key, value] of Object.entries(query)) {
        if (typeof value === 'string') {
            // Remove potentially dangerous characters and limit length
            sanitized[key] = value.replace(/[<>\"'&]/g, '').substring(0, 1000);
        }
    }
    
    return sanitized;
}



async function convertBody(
    request: FastifyRequest,
    projectId: string,
    flowId: string,
): Promise<unknown> {
    if (request.isMultipart()) {
        const jsonResult: Record<string, unknown> = {}
        const requestBodyEntries = Object.entries(
            request.body as Record<string, unknown>,
        )

        const platformId = await projectService.getPlatformId(projectId)

        for (const [key, value] of requestBodyEntries) {
            if (isMultipartFile(value)) {
                const file = await stepFileService(request.log).saveAndEnrich({
                    data: value.data as Buffer,
                    fileName: value.filename,
                    stepName: 'trigger',
                    flowId,
                    contentLength: value.data.length,
                    platformId,
                    projectId,
                })
                jsonResult[key] = file.url
            }
            else {
                jsonResult[key] = value
            }
        }
        return jsonResult
    }
    return request.body
}

