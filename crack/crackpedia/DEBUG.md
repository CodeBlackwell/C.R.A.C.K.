# CRACK Electron Debug System

Comprehensive debug logging system with categorized output and color coding.

## Quick Start

### Enable Debug Mode

```bash
# Enable all debug categories
DEBUG=true npm run dev

# Or set as environment variable
export DEBUG=true
npm run dev
```

### Enable Specific Categories

```bash
# Enable only Neo4j and IPC logs
DEBUG_CATEGORIES=NEO4J,IPC npm run dev

# Enable all categories (default)
DEBUG_CATEGORIES=* npm run dev
```

## Debug Categories

| Category | Emoji | Color | Purpose |
|----------|-------|-------|---------|
| **NEO4J** | 🔷 | Cyan | Neo4j driver, connections, session management |
| **IPC** | 📡 | Magenta | Inter-process communication between main/renderer |
| **ELECTRON** | ⚡ | Blue | Electron app lifecycle, windows, events |
| **QUERY** | 🔍 | Yellow | Cypher query execution and results |
| **ERROR** | ❌ | Red | All errors and failures |
| **STARTUP** | 🚀 | Green | Application startup sequence |
| **PERFORMANCE** | ⏱️ | Gray | Timing and performance metrics |

## Output Format

```
🔷 [NEO4J      ] 12:34:56.789 +2.456s Creating Neo4j driver instance
   └─ { uri: 'bolt://127.0.0.1:7687', maxPoolSize: 50, timeout: 2000 }
```

**Format breakdown:**
- Emoji + Category (11 chars padded)
- Timestamp (HH:MM:SS.mmm)
- Elapsed time since start (+seconds)
- Message
- Optional data object (indented)

## Usage Examples

### Example 1: Debug Neo4j Connection Issues

```bash
# Enable only Neo4j logs
DEBUG_CATEGORIES=NEO4J npm run dev
```

**Output:**
```
🔷 [NEO4J      ] 12:00:00.100 +0.100s Neo4j configuration loaded
   └─ { uri: 'bolt://127.0.0.1:7687', user: 'neo4j', password: 'Neo***' }
🔷 [NEO4J      ] 12:00:00.105 +0.105s Creating Neo4j driver instance
   └─ { uri: 'bolt://127.0.0.1:7687', maxPoolSize: 50, timeout: 2000 }
🔷 [NEO4J      ] 12:00:00.120 +0.120s Neo4j driver created successfully
🔷 [NEO4J      ] 12:00:01.500 +1.500s Health check passed - connectivity verified
```

### Example 2: Debug IPC Communication

```bash
# Enable IPC and Query logs
DEBUG_CATEGORIES=IPC,QUERY npm run dev
```

**Output:**
```
📡 [IPC        ] 12:00:05.200 +5.200s IPC: search-commands called
   └─ { query: 'nmap', filters: undefined }
🔍 [QUERY      ] 12:00:05.201 +5.201s Executing Cypher query
   └─ { query: 'MATCH (c:Command) WHERE toLower(c.name) CONTAINS toLower($searchQuery)...', params: { searchQuery: 'nmap' } }
⏱️ [PERFORMANCE] 12:00:05.450 +5.450s Query completed
   └─ { duration_ms: 249, records: 45 }
🔍 [QUERY      ] 12:00:05.451 +5.451s Query results mapped successfully
   └─ { count: 45 }
📡 [IPC        ] 12:00:05.452 +5.452s IPC: search-commands completed
   └─ { resultCount: 45 }
```

### Example 3: Debug Everything

```bash
# Full debug output
DEBUG=true DEBUG_CATEGORIES=* npm run dev
```

### Example 4: Debug Performance Issues

```bash
# Focus on performance and queries
DEBUG_CATEGORIES=PERFORMANCE,QUERY npm run dev
```

**Shows:**
- Query execution times
- Record counts
- Mapping performance
- Session lifecycle

## Programmatic Control

### In Code (main process)

```typescript
import { debug, logNeo4j, logIPC } from './debug';

// Enable/disable at runtime
debug.setEnabled(true);

// Enable specific categories
debug.enableCategories(DebugCategory.NEO4J, DebugCategory.IPC);

// Disable categories
debug.disableCategories(DebugCategory.PERFORMANCE);

// Log messages
logNeo4j('Connection established', { host: '127.0.0.1' });
logIPC('Message received', { type: 'search', params: {...} });

// Measure execution time
const result = await debug.measure(
  DebugCategory.QUERY,
  'Search commands',
  async () => {
    return await runQuery(cypherQuery, params);
  }
);
```

## Debug Log Locations

### Console Output
All debug logs appear in the **terminal where you ran `npm run dev`**, not in the Electron DevTools console.

### Main Process vs Renderer Process
The debug system currently logs **main process only** (Neo4j, IPC, Electron lifecycle).

To see **renderer logs** (React components), use browser DevTools:
- Press `F12` or `Ctrl+Shift+I` in the Electron window
- Check the Console tab

## Common Debugging Scenarios

### Problem: Neo4j Won't Connect

```bash
DEBUG_CATEGORIES=NEO4J,ERROR npm run dev
```

**Look for:**
- ❌ Authentication errors
- ❌ Connection refused
- 🔷 URI being used
- 🔷 Password (first 3 chars shown)

### Problem: Search Returns No Results

```bash
DEBUG_CATEGORIES=QUERY,IPC npm run dev
```

**Look for:**
- 🔍 Query being executed
- ⏱️ Query duration
- 🔍 Record count returned
- 📡 IPC result count

### Problem: Graph Won't Load

```bash
DEBUG_CATEGORIES=IPC,QUERY,ERROR npm run dev
```

**Look for:**
- 📡 get-graph IPC call
- 🔍 Graph query execution
- ⏱️ Query performance
- 📡 Node/edge counts returned

### Problem: App Won't Start

```bash
DEBUG_CATEGORIES=STARTUP,ELECTRON,ERROR npm run dev
```

**Look for:**
- 🚀 Startup sequence
- ⚡ Window creation
- ⚡ Dev server loading
- ❌ Any errors

## Performance Monitoring

Enable performance logs to track timing:

```bash
DEBUG_CATEGORIES=PERFORMANCE npm run dev
```

**Metrics tracked:**
- Query execution time (ms)
- Number of records processed
- IPC call overhead
- Session open/close timing

## Tips

1. **Start Specific**: Enable only categories you need
2. **Check Elapsed Time**: The `+X.XXXs` shows time since app start
3. **Color Coding**: Use colors to quickly scan for category types
4. **Data Objects**: Nested objects show detailed context
5. **Terminal Output**: All logs go to terminal, not DevTools

## Disable Debug Mode

```bash
# Don't set DEBUG variable
npm run dev

# Or explicitly disable
DEBUG=false npm run dev
```

## Integration with External Tools

### Save Logs to File

```bash
DEBUG=true npm run dev 2>&1 | tee debug.log
```

### Filter with grep

```bash
DEBUG=true npm run dev 2>&1 | grep "NEO4J"
DEBUG=true npm run dev 2>&1 | grep "ERROR"
```

### Watch for Errors Only

```bash
DEBUG_CATEGORIES=ERROR npm run dev
```

## Advanced: Custom Debug Categories

To add new categories, edit `src/main/debug.ts`:

```typescript
export enum DebugCategory {
  // ... existing ...
  CUSTOM = 'CUSTOM',
}

// Add emoji and color
private getCategoryEmoji(category: DebugCategory): string {
  const emojis: Record<DebugCategory, string> = {
    // ... existing ...
    [DebugCategory.CUSTOM]: '🎯',
  };
  return emojis[category] || '📌';
}
```

Then use it:

```typescript
import { debug, DebugCategory } from './debug';
debug.log(DebugCategory.CUSTOM, 'Custom message', { data: 'here' });
```

## Troubleshooting the Debug System

### Debug Logs Not Showing

1. Check environment variable is set:
   ```bash
   echo $DEBUG  # Should show "true" or "1"
   ```

2. Check categories are enabled:
   ```bash
   echo $DEBUG_CATEGORIES  # Should show categories or "*"
   ```

3. Logs only appear in **terminal**, not DevTools console

### Too Much Output

```bash
# Reduce to specific categories
DEBUG_CATEGORIES=ERROR,NEO4J npm run dev

# Or disable debug entirely
npm run dev
```

## Default Configuration

**Current defaults** (when no env vars set):
- Debug: **DISABLED** (must explicitly enable)
- Categories: **ALL** (when enabled)

To change defaults, edit `src/main/debug.ts` constructor.

---

**Quick Reference:**

```bash
# Enable everything
DEBUG=true npm run dev

# Enable specific
DEBUG_CATEGORIES=NEO4J,IPC npm run dev

# Save to file
DEBUG=true npm run dev 2>&1 | tee debug.log

# Watch errors
DEBUG_CATEGORIES=ERROR npm run dev
```
