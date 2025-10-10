import { FastifyBaseLogger } from 'fastify';
import {
    AIxBlockError,
    AIxBlockTaskStatus,
    apId,
    assertNotNullOrUndefined,
    ErrorCode,
    isNil,
    PlatformRole,
    StoreEntry,
} from 'workflow-shared';
import { userIdentityRepository } from '../../../authentication/user-identity/user-identity-service';
import { repoFactory } from '../../../core/db/repo-factory';
import { StoreEntryEntity } from '../../../store-entry/store-entry-entity';
import { userService } from '../../../user/user-service';
import { getScopeAndKey, PieceStoreScope } from '../aixblock-web-forms/aixblock-web-forms.service';
import { flowRepo } from '../flow.repo';

const storeEntryRepo = repoFactory<StoreEntry>(StoreEntryEntity);

export const aixblockAssignTasksService = (log: FastifyBaseLogger) => ({
    getDataSource: async (
        assignee: string,
        flowId: string,
        flowRunId: string,
        flowVersionId: string,
        stepName: string,
        mappingKey: string,
        userId: string
    ) => {
        await hasPermissionWithAssignee(assignee, userId);
        const { dataSource } = await getDatasourceByKeyAndFlowId(mappingKey, flowId, flowRunId);

        const rawData = dataSource.filter((item: any) => item.assignee === assignee);

        return {
            dataSource: rawData,
        };
    },

    submitForm: async (data: any, assignee: string, flowId: string, flowRunId: string, mappingKey: string, dataSourceId: string, userId: string) => {
        await hasPermissionWithAssignee(assignee, userId);
        const { dataSource, storeKeyRawDataSource, projectId } = await getDatasourceByKeyAndFlowId(mappingKey, flowId, flowRunId);
        const newDataSource = dataSource.map((item: any) => {
            if (item.id === dataSourceId) {
                const newProperties: any = {};
                for (const [fieldName, fieldData] of Object.entries(item.properties)) {
                    const value = data[fieldName];
                    newProperties[fieldName] = {
                        ...(fieldData as any),
                        value,
                    };
                }
                item.properties = newProperties;
            }
            return item;
        });
        await storeEntryRepo().upsert(
            {
                id: apId(),
                key: storeKeyRawDataSource,
                value: newDataSource,
                projectId,
            },
            ['projectId', 'key']
        );
        return {};
    },

    updateStatusDataSource: async (
        data: any,
        assignee: string,
        flowId: string,
        mappingKey: string,
        flowRunId: string,
        dataSourceId: string,
        userId: string
    ) => {
        await hasPermissionWithAssignee(assignee, userId);
        const { dataSource, storeKeyRawDataSource, projectId } = await getDatasourceByKeyAndFlowId(mappingKey, flowId, flowRunId);
        const newDataSource = dataSource.map((item: any) => {
            if (item.id === dataSourceId) {
                item.status = data.status ?? AIxBlockTaskStatus.TODO;
            }
            return item;
        });
        await storeEntryRepo().upsert(
            {
                id: apId(),
                key: storeKeyRawDataSource,
                value: newDataSource,
                projectId,
            },
            ['projectId', 'key']
        );
        return {};
    },
});

async function getDatasourceByKeyAndFlowId(mappingKey: string, flowId: string, flowRunId: string) {
    const flow = await flowRepo().findOneBy({ id: flowId });
    if (isNil(flow)) {
        throw new AIxBlockError({
            code: ErrorCode.FLOW_FORM_NOT_FOUND,
            params: {
                flowId,
                message: 'Flow form not found in draft version of flow.',
            },
        });
    }
    const storeKeyRawDataSource = getScopeAndKey(PieceStoreScope.FLOW, mappingKey, flowId, flowRunId).key;
    const storeRawDataSource = await storeEntryRepo().findOne({
        where: {
            key: storeKeyRawDataSource,
        },
    });
    if (isNil(storeRawDataSource)) {
        throw new AIxBlockError({
            code: ErrorCode.FLOW_FORM_NOT_FOUND,
            params: {
                flowId,
                message: 'Can not find raw data source',
            },
        });
    }
    const rawDataSource = storeRawDataSource.value as any[];
    return {
        dataSource: rawDataSource,
        storeKeyRawDataSource,
        projectId: flow.projectId,
    };
}

async function hasPermissionWithAssignee(assignee: string, userId: string) {
    assertNotNullOrUndefined(userId, 'userId');

    // Security fix: Validate email format to prevent injection attacks
    if (!isValidEmail(assignee)) {
        throw new AIxBlockError({
            code: ErrorCode.VALIDATION,
            params: {
                message: 'Invalid email format for assignee.',
            },
        });
    }

    const user = await userService.getOneOrFail({ id: userId });
    const identity = await userIdentityRepository().findOneByOrFail({ id: user.identityId });
    
    // Security fix: Remove console.log statements that expose sensitive information
    // console.log('user', user); // REMOVED FOR SECURITY
    // console.log('identity', identity); // REMOVED FOR SECURITY

    // Admin can view all tasks
    if (user.platformRole === PlatformRole.ADMIN) return;

    // Security fix: Use strict equality and proper email validation
    if (user.externalId && user.externalId === assignee) return;

    // Compare with email with internal email in workflow platform
    if (identity.email === assignee) return;

    throw new AIxBlockError({
        code: ErrorCode.AUTHORIZATION,
        params: {
            message: 'Current email does not match with assignee.',
        },
    });
}

// Security helper function to validate email format
function isValidEmail(email: string): boolean {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email) && email.length <= 254;
}
