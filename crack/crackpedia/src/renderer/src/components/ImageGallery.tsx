import { useState } from 'react'
import { Box, Image, Text, SimpleGrid, Card, Group, Badge, Tooltip } from '@mantine/core'
import { IconPhoto } from '@tabler/icons-react'
import { ScreenshotReference } from '../types/writeup'
import { ImageLightbox } from './ImageLightbox'

interface ImageGalleryProps {
  images: ScreenshotReference[]
  baseImagePath: string // e.g., "/home/kali/Desktop/OSCP/crack/db/data/writeups/hackthebox/Usage/"
  layout?: 'inline' | 'grid'
  showCaptions?: boolean
}

export function ImageGallery({
  images,
  baseImagePath,
  layout = 'grid',
  showCaptions = true
}: ImageGalleryProps) {
  const [lightboxOpened, setLightboxOpened] = useState(false)
  const [selectedImageIndex, setSelectedImageIndex] = useState(0)

  if (!images || images.length === 0) {
    return null
  }

  const handleImageClick = (index: number) => {
    setSelectedImageIndex(index)
    setLightboxOpened(true)
  }

  const handleLightboxClose = () => {
    setLightboxOpened(false)
  }

  const handleNavigate = (index: number) => {
    setSelectedImageIndex(index)
  }

  // Inline layout - horizontal scrolling thumbnails
  if (layout === 'inline') {
    return (
      <Box>
        <Group gap="sm" style={{ overflowX: 'auto', padding: '8px 0' }}>
          {images.map((image, index) => (
            <Card
              key={index}
              padding="xs"
              style={{
                minWidth: '150px',
                cursor: 'pointer',
                backgroundColor: '#25262b',
                border: '1px solid #373A40',
                transition: 'transform 0.2s',
                flex: '0 0 auto'
              }}
              onClick={() => handleImageClick(index)}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'scale(1.05)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'scale(1)'
              }}
            >
              <Image
                src={`file://${baseImagePath}/${image.file}`}
                alt={image.caption || 'Screenshot'}
                height={100}
                fit="cover"
                style={{ borderRadius: '4px' }}
              />
              {showCaptions && image.caption && (
                <Text
                  size="xs"
                  mt="xs"
                  lineClamp={2}
                  style={{ color: '#909296' }}
                >
                  {image.caption}
                </Text>
              )}
              {image.confidence && (
                <Badge
                  size="xs"
                  color={
                    image.confidence === 'high'
                      ? 'green'
                      : image.confidence === 'medium'
                        ? 'yellow'
                        : 'gray'
                  }
                  mt="xs"
                >
                  {image.confidence}
                </Badge>
              )}
            </Card>
          ))}
        </Group>

        <ImageLightbox
          images={images}
          currentIndex={selectedImageIndex}
          opened={lightboxOpened}
          onClose={handleLightboxClose}
          onNavigate={handleNavigate}
          baseImagePath={baseImagePath}
        />
      </Box>
    )
  }

  // Grid layout - responsive grid
  return (
    <Box>
      <Group mb="md" gap="xs">
        <IconPhoto size={16} style={{ color: '#22c1c3' }} />
        <Text size="sm" fw={500}>
          Screenshots ({images.length})
        </Text>
      </Group>

      <SimpleGrid
        cols={{ base: 1, sm: 2, md: 3, lg: 4 }}
        spacing="md"
      >
        {images.map((image, index) => (
          <Tooltip
            key={index}
            label={image.caption || image.file}
            position="top"
            withArrow
          >
            <Card
              padding="xs"
              style={{
                cursor: 'pointer',
                backgroundColor: '#25262b',
                border: '1px solid #373A40',
                transition: 'all 0.2s'
              }}
              onClick={() => handleImageClick(index)}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-4px)'
                e.currentTarget.style.boxShadow = '0 4px 12px rgba(34, 193, 195, 0.2)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)'
                e.currentTarget.style.boxShadow = 'none'
              }}
            >
              <Image
                src={`file://${baseImagePath}/${image.file}`}
                alt={image.caption || 'Screenshot'}
                height={150}
                fit="cover"
                style={{ borderRadius: '4px', backgroundColor: '#1a1b1e' }}
              />

              {showCaptions && (
                <Box mt="xs">
                  {image.caption && (
                    <Text
                      size="xs"
                      lineClamp={2}
                      style={{ color: '#909296', minHeight: '32px' }}
                    >
                      {image.caption}
                    </Text>
                  )}
                  <Group gap="xs" mt="xs">
                    {image.extracted_from_page && (
                      <Text size="xs" c="dimmed">
                        Page {image.extracted_from_page}
                      </Text>
                    )}
                    {image.confidence && (
                      <Badge
                        size="xs"
                        color={
                          image.confidence === 'high'
                            ? 'green'
                            : image.confidence === 'medium'
                              ? 'yellow'
                              : 'gray'
                        }
                      >
                        {image.confidence}
                      </Badge>
                    )}
                  </Group>
                </Box>
              )}
            </Card>
          </Tooltip>
        ))}
      </SimpleGrid>

      <ImageLightbox
        images={images}
        currentIndex={selectedImageIndex}
        opened={lightboxOpened}
        onClose={handleLightboxClose}
        onNavigate={handleNavigate}
        baseImagePath={baseImagePath}
      />
    </Box>
  )
}
