#!/usr/bin/env python3
"""
Populate Neo4j with comprehensive test data for advanced query pattern testing.

This script creates realistic OSCP-focused data including:
- Commands with all properties
- Relationships: ALTERNATIVE, PREREQUISITE, NEXT_STEP, TAGGED, etc.
- Attack chains with dependencies
- Services and ports
- Tag hierarchies
"""

from neo4j import GraphDatabase
import sys


class Neo4jTestDataPopulator:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="Afrodeeziak21"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def clear_database(self):
        """Clear all data (for testing only)"""
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
            print("✓ Database cleared")

    def create_constraints(self):
        """Create constraints and indexes"""
        with self.driver.session() as session:
            constraints = [
                "CREATE CONSTRAINT cmd_id IF NOT EXISTS FOR (c:Command) REQUIRE c.id IS UNIQUE",
                "CREATE CONSTRAINT tag_name IF NOT EXISTS FOR (t:Tag) REQUIRE t.name IS UNIQUE",
                "CREATE CONSTRAINT var_name IF NOT EXISTS FOR (v:Variable) REQUIRE v.name IS UNIQUE",
                "CREATE INDEX cmd_oscp IF NOT EXISTS FOR (c:Command) ON (c.oscp_relevance)",
                "CREATE INDEX cmd_category IF NOT EXISTS FOR (c:Command) ON (c.category)",
            ]
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception as e:
                    print(f"  Note: {e}")
            print("✓ Constraints and indexes created")

    def create_commands(self):
        """Create realistic OSCP commands"""
        commands = [
            # Enumeration commands
            {
                'id': 'nmap-quick-scan', 'name': 'Nmap Quick Scan',
                'category': 'ENUMERATION', 'subcategory': 'PORT_SCANNING',
                'oscp_relevance': 'high', 'priority': 1,
                'description': 'Fast port scan', 'tags': ['STARTER', 'QUICK_WIN']
            },
            {
                'id': 'nmap-service-enum', 'name': 'Nmap Service Enumeration',
                'category': 'ENUMERATION', 'subcategory': 'SERVICE_DETECTION',
                'oscp_relevance': 'high', 'priority': 2,
                'description': 'Detailed service scan', 'tags': ['OSCP:ENUM']
            },
            {
                'id': 'gobuster-dir', 'name': 'Gobuster Directory Enumeration',
                'category': 'ENUMERATION', 'subcategory': 'WEB',
                'oscp_relevance': 'high', 'priority': 3,
                'description': 'Directory bruteforce', 'tags': ['OSCP:ENUM', 'WEB']
            },
            {
                'id': 'ffuf-dir', 'name': 'FFUF Directory Fuzzing',
                'category': 'ENUMERATION', 'subcategory': 'WEB',
                'oscp_relevance': 'high', 'priority': 3,
                'description': 'Fast web fuzzer', 'tags': ['OSCP:ENUM', 'WEB']
            },
            {
                'id': 'wfuzz-dir', 'name': 'Wfuzz Directory Enumeration',
                'category': 'ENUMERATION', 'subcategory': 'WEB',
                'oscp_relevance': 'medium', 'priority': 4,
                'description': 'Web fuzzer', 'tags': ['WEB']
            },
            {
                'id': 'nikto-scan', 'name': 'Nikto Web Scanner',
                'category': 'ENUMERATION', 'subcategory': 'WEB',
                'oscp_relevance': 'high', 'priority': 5,
                'description': 'Web vulnerability scanner', 'tags': ['OSCP:ENUM', 'WEB']
            },

            # Exploitation commands
            {
                'id': 'wordpress-sqli', 'name': 'WordPress SQLi Exploit',
                'category': 'EXPLOITATION', 'subcategory': 'WEB',
                'oscp_relevance': 'high', 'priority': 10,
                'description': 'SQL injection attack', 'tags': ['OSCP:EXPLOIT', 'WEB']
            },
            {
                'id': 'smb-exploit', 'name': 'SMB EternalBlue Exploit',
                'category': 'EXPLOITATION', 'subcategory': 'NETWORK',
                'oscp_relevance': 'high', 'priority': 10,
                'description': 'SMB vulnerability exploit', 'tags': ['OSCP:EXPLOIT']
            },

            # Privilege escalation
            {
                'id': 'linpeas', 'name': 'LinPEAS Enumeration',
                'category': 'PRIVESC', 'subcategory': 'LINUX',
                'oscp_relevance': 'high', 'priority': 15,
                'description': 'Linux privilege escalation scanner', 'tags': ['PRIVESC', 'OSCP:PRIVESC']
            },
            {
                'id': 'sudo-exploit', 'name': 'Sudo Privilege Escalation',
                'category': 'PRIVESC', 'subcategory': 'LINUX',
                'oscp_relevance': 'high', 'priority': 20,
                'description': 'Exploit sudo misconfiguration', 'tags': ['PRIVESC', 'OSCP:PRIVESC']
            },
        ]

        with self.driver.session() as session:
            for cmd in commands:
                tags = cmd.pop('tags')
                session.run("""
                    CREATE (c:Command $props)
                """, props=cmd)

                # Create tag relationships
                for tag in tags:
                    session.run("""
                        MATCH (c:Command {id: $cmd_id})
                        MERGE (t:Tag {name: $tag_name})
                        MERGE (c)-[:TAGGED]->(t)
                    """, cmd_id=cmd['id'], tag_name=tag)

            print(f"✓ Created {len(commands)} commands with tags")

    def create_tag_hierarchy(self):
        """Create tag parent-child relationships"""
        hierarchies = [
            ('OSCP:ENUM', 'OSCP'),
            ('OSCP:EXPLOIT', 'OSCP'),
            ('OSCP:PRIVESC', 'OSCP'),
        ]

        with self.driver.session() as session:
            for child, parent in hierarchies:
                session.run("""
                    MERGE (child:Tag {name: $child})
                    MERGE (parent:Tag {name: $parent})
                    MERGE (child)-[:CHILD_OF]->(parent)
                """, child=child, parent=parent)
            print(f"✓ Created {len(hierarchies)} tag hierarchy relationships")

    def create_alternatives(self):
        """Create ALTERNATIVE relationships"""
        alternatives = [
            ('gobuster-dir', 'ffuf-dir', 1, 'Faster for small wordlists'),
            ('ffuf-dir', 'wfuzz-dir', 2, 'More features'),
            ('gobuster-dir', 'wfuzz-dir', 3, '2-hop alternative'),
        ]

        with self.driver.session() as session:
            for cmd1, cmd2, priority, reason in alternatives:
                session.run("""
                    MATCH (c1:Command {id: $cmd1})
                    MATCH (c2:Command {id: $cmd2})
                    MERGE (c1)-[r:ALTERNATIVE]->(c2)
                    SET r.priority = $priority, r.reason = $reason
                """, cmd1=cmd1, cmd2=cmd2, priority=priority, reason=reason)
            print(f"✓ Created {len(alternatives)} ALTERNATIVE relationships")

    def create_prerequisites(self):
        """Create PREREQUISITE relationships"""
        prerequisites = [
            ('nmap-service-enum', 'nmap-quick-scan'),
            ('gobuster-dir', 'nmap-service-enum'),
            ('wordpress-sqli', 'gobuster-dir'),
            ('sudo-exploit', 'linpeas'),
        ]

        with self.driver.session() as session:
            for cmd, prereq in prerequisites:
                session.run("""
                    MATCH (c:Command {id: $cmd})
                    MATCH (p:Command {id: $prereq})
                    MERGE (c)-[:PREREQUISITE]->(p)
                """, cmd=cmd, prereq=prereq)
            print(f"✓ Created {len(prerequisites)} PREREQUISITE relationships")

    def create_next_steps(self):
        """Create NEXT_STEP workflow relationships"""
        steps = [
            ('nmap-quick-scan', 'nmap-service-enum'),
            ('nmap-service-enum', 'gobuster-dir'),
            ('gobuster-dir', 'wordpress-sqli'),
            ('wordpress-sqli', 'linpeas'),
            ('linpeas', 'sudo-exploit'),
        ]

        with self.driver.session() as session:
            for from_cmd, to_cmd in steps:
                session.run("""
                    MATCH (from:Command {id: $from_cmd})
                    MATCH (to:Command {id: $to_cmd})
                    MERGE (from)-[:NEXT_STEP]->(to)
                """, from_cmd=from_cmd, to_cmd=to_cmd)
            print(f"✓ Created {len(steps)} NEXT_STEP relationships")

    def create_services_and_ports(self):
        """Create Service and Port nodes with relationships"""
        services = [
            {'name': 'http', 'protocol': 'TCP', 'port': 80, 'commands': ['gobuster-dir', 'ffuf-dir', 'nikto-scan']},
            {'name': 'smb', 'protocol': 'TCP', 'port': 445, 'commands': ['smb-exploit']},
            {'name': 'ssh', 'protocol': 'TCP', 'port': 22, 'commands': []},
        ]

        with self.driver.session() as session:
            for svc in services:
                # Create port and service
                session.run("""
                    MERGE (p:Port {number: $port, protocol: $protocol})
                    MERGE (s:Service {name: $name, protocol: $protocol})
                    MERGE (s)-[:RUNS_ON]->(p)
                """, port=svc['port'], protocol=svc['protocol'], name=svc['name'])

                # Link to commands
                for cmd_id in svc['commands']:
                    session.run("""
                        MATCH (s:Service {name: $service})
                        MATCH (c:Command {id: $cmd_id})
                        MERGE (s)-[:ENUMERATED_BY {priority: 1}]->(c)
                    """, service=svc['name'], cmd_id=cmd_id)

            print(f"✓ Created {len(services)} services with port mappings")

    def create_variables(self):
        """Create Variable nodes"""
        variables = [
            {'name': '<TARGET>', 'description': 'Target IP or hostname', 'required': True},
            {'name': '<PORT>', 'description': 'Target port', 'required': True},
            {'name': '<WORDLIST>', 'description': 'Wordlist path', 'required': False},
        ]

        with self.driver.session() as session:
            for var in variables:
                session.run("""
                    CREATE (v:Variable $props)
                """, props=var)

                # Link some commands to variables
                if var['name'] == '<TARGET>':
                    session.run("""
                        MATCH (v:Variable {name: $var_name})
                        MATCH (c:Command)
                        WHERE c.id IN ['nmap-quick-scan', 'gobuster-dir', 'wordpress-sqli']
                        MERGE (c)-[r:USES_VARIABLE]->(v)
                        SET r.required = true, r.example = '10.10.10.1'
                    """, var_name=var['name'])

            print(f"✓ Created {len(variables)} variables with command links")

    def create_attack_chain(self):
        """Create attack chain with steps and dependencies"""
        with self.driver.session() as session:
            # Create chain
            session.run("""
                CREATE (chain:AttackChain {
                    id: 'web-to-root',
                    name: 'Web Application to Root',
                    description: 'Common OSCP web exploitation path',
                    difficulty: 'medium',
                    oscp_relevant: true
                })
            """)

            # Create steps
            steps = [
                {'id': 'step1', 'name': 'Port Scan', 'order': 1, 'cmd': 'nmap-quick-scan', 'deps': []},
                {'id': 'step2', 'name': 'Service Enum', 'order': 2, 'cmd': 'nmap-service-enum', 'deps': ['step1']},
                {'id': 'step3', 'name': 'Web Enum', 'order': 3, 'cmd': 'gobuster-dir', 'deps': ['step2']},
                {'id': 'step4', 'name': 'Exploit Web', 'order': 4, 'cmd': 'wordpress-sqli', 'deps': ['step3']},
                {'id': 'step5', 'name': 'Privesc Enum', 'order': 5, 'cmd': 'linpeas', 'deps': ['step4']},
                {'id': 'step6', 'name': 'Root Exploit', 'order': 6, 'cmd': 'sudo-exploit', 'deps': ['step5']},
            ]

            for step in steps:
                session.run("""
                    MATCH (chain:AttackChain {id: 'web-to-root'})
                    MATCH (cmd:Command {id: $cmd_id})
                    CREATE (step:ChainStep {
                        id: $step_id,
                        name: $step_name,
                        step_order: $order,
                        chain_id: 'web-to-root'
                    })
                    CREATE (chain)-[:HAS_STEP]->(step)
                    CREATE (step)-[:EXECUTES]->(cmd)
                """, step_id=step['id'], step_name=step['name'],
                     order=step['order'], cmd_id=step['cmd'])

                # Create dependencies
                for dep in step['deps']:
                    session.run("""
                        MATCH (step:ChainStep {id: $step_id})
                        MATCH (dep:ChainStep {id: $dep_id})
                        CREATE (step)-[:DEPENDS_ON]->(dep)
                    """, step_id=step['id'], dep_id=dep)

            print(f"✓ Created attack chain with {len(steps)} steps")

    def verify_data(self):
        """Verify data was created correctly"""
        with self.driver.session() as session:
            stats = {
                'commands': session.run("MATCH (c:Command) RETURN count(c) AS count").single()['count'],
                'tags': session.run("MATCH (t:Tag) RETURN count(t) AS count").single()['count'],
                'alternatives': session.run("MATCH ()-[r:ALTERNATIVE]->() RETURN count(r) AS count").single()['count'],
                'prerequisites': session.run("MATCH ()-[r:PREREQUISITE]->() RETURN count(r) AS count").single()['count'],
                'next_steps': session.run("MATCH ()-[r:NEXT_STEP]->() RETURN count(r) AS count").single()['count'],
                'services': session.run("MATCH (s:Service) RETURN count(s) AS count").single()['count'],
                'variables': session.run("MATCH (v:Variable) RETURN count(v) AS count").single()['count'],
                'attack_chains': session.run("MATCH (a:AttackChain) RETURN count(a) AS count").single()['count'],
                'chain_steps': session.run("MATCH (s:ChainStep) RETURN count(s) AS count").single()['count'],
            }

            print("\n📊 Database Statistics:")
            for key, value in stats.items():
                print(f"  {key:20s}: {value}")

            return stats

    def populate_all(self):
        """Run all population steps"""
        print("\n🗄️  Populating Neo4j Test Database...\n")

        self.clear_database()
        self.create_constraints()
        self.create_commands()
        self.create_tag_hierarchy()
        self.create_alternatives()
        self.create_prerequisites()
        self.create_next_steps()
        self.create_services_and_ports()
        self.create_variables()
        self.create_attack_chain()

        stats = self.verify_data()

        print("\n✅ Database population complete!\n")
        return stats


if __name__ == "__main__":
    try:
        populator = Neo4jTestDataPopulator()
        stats = populator.populate_all()
        populator.close()
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
