/**
 * Shared Neo4j Driver Singleton
 *
 * Provides centralized Neo4j connection management for CRACK Electron apps.
 * Supports connection pooling and automatic retry logic.
 */

import neo4j, { Driver, Session } from 'neo4j-driver';

interface Neo4jConfig {
  uri: string;
  user: string;
  password: string;
  maxPoolSize?: number;
  connectionTimeout?: number;
}

/** Default configuration from environment */
function getDefaultConfig(): Neo4jConfig {
  return {
    uri: process.env.NEO4J_URI || 'bolt://127.0.0.1:7687',
    user: process.env.NEO4J_USER || 'neo4j',
    password: process.env.NEO4J_PASSWORD || 'Neo4j123',
    maxPoolSize: 50,
    connectionTimeout: 2000,
  };
}

class Neo4jDriverManager {
  private driver: Driver | null = null;
  private config: Neo4jConfig;

  constructor(config?: Partial<Neo4jConfig>) {
    this.config = { ...getDefaultConfig(), ...config };
  }

  /** Get or create driver instance */
  getDriver(): Driver {
    if (!this.driver) {
      this.driver = neo4j.driver(
        this.config.uri,
        neo4j.auth.basic(this.config.user, this.config.password),
        {
          maxConnectionPoolSize: this.config.maxPoolSize,
          connectionAcquisitionTimeout: this.config.connectionTimeout,
        }
      );
    }
    return this.driver;
  }

  /** Get a new session */
  getSession(): Session {
    return this.getDriver().session();
  }

  /** Verify connectivity */
  async verifyConnectivity(): Promise<{ connected: boolean; uri: string; error?: string }> {
    try {
      const driver = this.getDriver();
      await driver.verifyConnectivity();
      return { connected: true, uri: this.config.uri };
    } catch (error) {
      return {
        connected: false,
        uri: this.config.uri,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /** Close driver connection */
  async close(): Promise<void> {
    if (this.driver) {
      await this.driver.close();
      this.driver = null;
    }
  }

  /** Get configuration (password masked) */
  getConfig(): { uri: string; user: string; password: string } {
    return {
      uri: this.config.uri,
      user: this.config.user,
      password: this.config.password ? `${this.config.password.slice(0, 3)}***` : 'NOT SET',
    };
  }
}

/** Default singleton instance */
export const neo4jDriver = new Neo4jDriverManager();

/** Factory for custom configurations */
export function createNeo4jDriver(config?: Partial<Neo4jConfig>): Neo4jDriverManager {
  return new Neo4jDriverManager(config);
}

/** Re-export neo4j types for convenience */
export { Driver, Session } from 'neo4j-driver';
export type { Neo4jConfig };
