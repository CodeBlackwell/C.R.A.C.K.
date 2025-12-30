<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" indent="yes" />
  <xsl:template match="/">
    <html>
      <body>
        <h1>Data:</h1>
        <pre><xsl:value-of select="//item"/></pre>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
