import { useEffect } from 'react';
import { Paper, Text, Center } from '@mantine/core';

export default function ChainView() {
  useEffect(() => {
    console.log('[ChainView] Component mounted');
  }, []);

  return (
    <Paper
      shadow="sm"
      p="md"
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <Text size="lg" fw={600} mb="md">
        Chains
      </Text>
      <Center style={{ flex: 1 }}>
        <Text c="dimmed" size="sm" style={{ textAlign: 'center' }}>
          Chain view coming soon...
        </Text>
      </Center>
    </Paper>
  );
}
