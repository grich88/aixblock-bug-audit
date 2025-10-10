import cors from '@fastify/cors'
import formBody from '@fastify/formbody'
import fastifyMultipart, { MultipartFile } from '@fastify/multipart'
import fastify, { FastifyBaseLogger, FastifyInstance } from 'fastify'
import fastifyFavicon from 'fastify-favicon'
import { fastifyRawBody } from 'fastify-raw-body'
import qs from 'qs'
import path from 'path'
import rateLimit from '@fastify/rate-limit'
import { AppSystemProp, exceptionHandler } from 'workflow-server-shared'
import { apId, ApMultipartFile, AIxBlockError, ErrorCode } from 'workflow-shared'
import { setupApp } from './app'
import { healthModule } from './health/health.module'
import { errorHandler } from './helper/error-handler'
import { system } from './helper/system/system'
import { setupWorker } from './worker'


export const setupServer = async (): Promise<FastifyInstance> => {
    const app = await setupBaseApp()

    if (system.isApp()) {
        await setupApp(app)
    }
    if (system.isWorker()) {
        await setupWorker(app)
    }
    return app
}

async function setupBaseApp(): Promise<FastifyInstance> {
    const MAX_FILE_SIZE_MB = system.getNumberOrThrow(AppSystemProp.MAX_FILE_SIZE_MB)
    const fileSizeLimit =  Math.max(25 * 1024 * 1024, (MAX_FILE_SIZE_MB + 4) * 1024 * 1024)
    const app = fastify({
        logger: system.globalLogger() as FastifyBaseLogger,
        ignoreTrailingSlash: true,
        pluginTimeout: 30000,
        // Default 100MB, also set in nginx.conf
        bodyLimit: fileSizeLimit,
        genReqId: () => {
            return `req_${apId()}`
        },
        ajv: {
            customOptions: {
                removeAdditional: 'all',
                useDefaults: true,
                keywords: ['discriminator'],
                coerceTypes: 'array',
                formats: {},
            },
        },
    }) 
    await app.register(fastifyFavicon)
    
    // Security fix: Add rate limiting to prevent DoS attacks
    await app.register(rateLimit, {
        max: 100,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip,
        errorResponseBuilder: (request, context) => ({
            code: 429,
            error: 'Too Many Requests',
            message: `Rate limit exceeded, retry in ${context.after}`
        })
    })
    
    await app.register(fastifyMultipart, {
        attachFieldsToBody: 'keyValues',
        async onFile(part: MultipartFile) {
            // Security fix: Validate filename to prevent path traversal attacks
            if (!isValidFilename(part.filename)) {
                throw new AIxBlockError({
                    code: ErrorCode.VALIDATION,
                    params: { message: 'Invalid filename: path traversal detected' }
                });
            }
            
            // Security fix: Sanitize filename
            const sanitizedFilename = sanitizeFilename(part.filename);
            
            const apFile: ApMultipartFile = {
                filename: sanitizedFilename,
                data: await part.toBuffer(),
                type: 'file',
            };
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (part as any).value = apFile
        },
    })
    exceptionHandler.initializeSentry(system.get(AppSystemProp.SENTRY_DSN))


    await app.register(fastifyRawBody, {
        field: 'rawBody',
        global: false,
        encoding: 'utf8',
        runFirst: true,
        routes: [],
    })

    await app.register(formBody, { parser: (str) => qs.parse(str) })
    app.setErrorHandler(errorHandler)
    // Security fix: Restrict CORS to specific domains
    await app.register(cors, {
        origin: ['https://app.aixblock.io', 'https://api.aixblock.io'],
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
        exposedHeaders: ['Content-Length', 'X-Total-Count'],
    })
    // SurveyMonkey
    app.addContentTypeParser(
        'application/vnd.surveymonkey.response.v1+json',
        { parseAs: 'string' },
        app.getDefaultJsonParser('ignore', 'ignore'),
    )
    await app.register(healthModule)

    return app
}

// Security helper functions for file upload validation
function isValidFilename(filename: string): boolean {
    if (!filename || typeof filename !== 'string') {
        return false;
    }
    
    // Check for path traversal patterns
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
        return false;
    }
    
    // Check for null bytes
    if (filename.includes('\0')) {
        return false;
    }
    
    // Check file extension
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.csv', '.json', '.xml'];
    const extension = path.extname(filename).toLowerCase();
    if (!allowedExtensions.includes(extension)) {
        return false;
    }
    
    // Check filename length
    if (filename.length > 255) {
        return false;
    }
    
    return true;
}

function sanitizeFilename(filename: string): string {
    // Remove any remaining dangerous characters
    return filename
        .replace(/[^a-zA-Z0-9.-]/g, '_')
        .replace(/\.{2,}/g, '.')
        .replace(/^\.+|\.+$/g, '') // Remove leading/trailing dots
        .substring(0, 255);
}

