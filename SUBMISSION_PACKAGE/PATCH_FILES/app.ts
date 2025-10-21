// This is a partial file - only the CORS section that needs to be replaced
// Replace the fastifySocketIO registration section in the original app.ts file

await app.register(fastifySocketIO, {
    cors: {
        origin: [
            'https://app.aixblock.io',
            'https://workflow.aixblock.io',
            'https://workflow-live.aixblock.io'
        ],
        credentials: true
    },
    ...spreadIfDefined('adapter', await getAdapter()),
    transports: ['websocket'],
})
