import { createAction, Property } from 'workflow-blocks-framework';
import { mysqlCommon, mysqlConnect, warningMarkdown } from '../common';
import { mysqlAuth } from '../..';

export default createAction({
  auth: mysqlAuth,
  name: 'execute_query',
  displayName: 'Execute Query',
  description: 'Executes a query on the mysql database and returns the results',
  props: {
    markdown: warningMarkdown,
    timezone: mysqlCommon.timezone,
    query: Property.ShortText({
      displayName: 'Query',
      description: 'The query string to execute, use ? for arguments to avoid SQL injection.',
      required: true,
    }),
    args: Property.Array({
      displayName: 'Arguments',
      description: 'Arguments to use in the query, if any. Should be in the same order as the ? in the query string..',
      required: false,
    }),
  },
  async run(context) {
    // Security fix: Validate query to prevent SQL injection
    if (!isValidQuery(context.propsValue.query)) {
      throw new Error('Invalid query: Only SELECT queries are allowed for security reasons');
    }
    
    const conn = await mysqlConnect(context.auth, context.propsValue);
    try {
      const results = await conn.query(
        context.propsValue.query,
        context.propsValue.args || []
      );
      return Array.isArray(results) ? { results } : results;
    } finally {
      await conn.end();
    }
  },
});

// Security helper function to validate SQL queries
function isValidQuery(query: string): boolean {
  if (!query || typeof query !== 'string') {
    return false;
  }
  
  const trimmedQuery = query.trim().toLowerCase();
  
  // Only allow SELECT queries
  if (!trimmedQuery.startsWith('select')) {
    return false;
  }
  
  // Block dangerous SQL keywords
  const dangerousKeywords = [
    'drop', 'delete', 'update', 'insert', 'alter', 'create', 'truncate',
    'exec', 'execute', 'sp_', 'xp_', '--', '/*', '*/', 'union', 'script'
  ];
  
  for (const keyword of dangerousKeywords) {
    if (trimmedQuery.includes(keyword)) {
      return false;
    }
  }
  
  // Check for suspicious patterns
  if (trimmedQuery.includes('information_schema') || 
      trimmedQuery.includes('mysql.') ||
      trimmedQuery.includes('sys.')) {
    return false;
  }
  
  return true;
}
