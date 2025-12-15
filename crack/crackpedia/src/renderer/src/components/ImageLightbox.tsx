import { Modal, Image, Group, Button, Text, Box, ActionIcon, CloseButton } from '@mantine/core'
import { useHotkeys } from '@mantine/hooks'
import { IconChevronLeft, IconChevronRight, IconX } from '@tabler/icons-react'
import { ScreenshotReference } from '../types/writeup'

interface ImageLightboxProps {
  images: ScreenshotReference[]
  currentIndex: number
  opened: boolean
  onClose: () => void
  onNavigate: (index: number) => void
  baseImagePath: string // e.g., "/home/kali/Desktop/OSCP/crack/db/data/writeups/hackthebox/Usage/"
}

export function ImageLightbox({
  images,
  currentIndex,
  opened,
  onClose,
  onNavigate,
  baseImagePath
}: ImageLightboxProps) {
  const currentImage = images[currentIndex]
  const totalImages = images.length

  // Keyboard navigation
  useHotkeys([
    ['ArrowLeft', () => navigatePrevious()],
    ['ArrowRight', () => navigateNext()],
    ['Escape', () => onClose()]
  ])

  const navigatePrevious = () => {
    if (currentIndex > 0) {
      onNavigate(currentIndex - 1)
    }
  }

  const navigateNext = () => {
    if (currentIndex < totalImages - 1) {
      onNavigate(currentIndex + 1)
    }
  }

  if (!currentImage) {
    return null
  }

  // Convert relative path to file:// URL
  const imageUrl = `file://${baseImagePath}/${currentImage.file}`

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      size="90%"
      padding="md"
      title={
        <Group justify="space-between" style={{ width: '100%' }}>
          <Text size="sm" fw={500}>
            {currentImage.caption || currentImage.file}
          </Text>
          <Text size="xs" c="dimmed">
            {currentIndex + 1} / {totalImages}
          </Text>
        </Group>
      }
      styles={{
        body: { padding: 0 },
        header: {
          backgroundColor: '#25262b',
          borderBottom: '1px solid #373A40'
        },
        content: {
          backgroundColor: '#1a1b1e'
        }
      }}
    >
      <Box style={{ position: 'relative' }}>
        {/* Main Image */}
        <Image
          src={imageUrl}
          alt={currentImage.caption || 'Screenshot'}
          fit="contain"
          style={{
            maxHeight: '80vh',
            width: '100%',
            backgroundColor: '#1a1b1e'
          }}
        />

        {/* Navigation Arrows */}
        {currentIndex > 0 && (
          <ActionIcon
            size="lg"
            variant="filled"
            color="dark"
            onClick={navigatePrevious}
            style={{
              position: 'absolute',
              left: '10px',
              top: '50%',
              transform: 'translateY(-50%)',
              opacity: 0.8
            }}
          >
            <IconChevronLeft size={24} />
          </ActionIcon>
        )}

        {currentIndex < totalImages - 1 && (
          <ActionIcon
            size="lg"
            variant="filled"
            color="dark"
            onClick={navigateNext}
            style={{
              position: 'absolute',
              right: '10px',
              top: '50%',
              transform: 'translateY(-50%)',
              opacity: 0.8
            }}
          >
            <IconChevronRight size={24} />
          </ActionIcon>
        )}

        {/* Image Info Footer */}
        {(currentImage.caption || currentImage.context || currentImage.extracted_from_page) && (
          <Box
            p="md"
            style={{
              backgroundColor: '#25262b',
              borderTop: '1px solid #373A40'
            }}
          >
            {currentImage.caption && (
              <Text size="sm" mb="xs">
                {currentImage.caption}
              </Text>
            )}
            <Group gap="md">
              {currentImage.extracted_from_page && (
                <Text size="xs" c="dimmed">
                  Page {currentImage.extracted_from_page}
                </Text>
              )}
              {currentImage.confidence && (
                <Text
                  size="xs"
                  c={
                    currentImage.confidence === 'high'
                      ? 'green'
                      : currentImage.confidence === 'medium'
                        ? 'yellow'
                        : 'gray'
                  }
                >
                  Confidence: {currentImage.confidence}
                </Text>
              )}
            </Group>
            {currentImage.context && (
              <Text size="xs" c="dimmed" mt="xs" style={{ fontStyle: 'italic' }}>
                {currentImage.context}
              </Text>
            )}
          </Box>
        )}
      </Box>
    </Modal>
  )
}
