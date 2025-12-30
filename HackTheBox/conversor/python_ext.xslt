<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:py="urn:python"
    xmlns:dyn="http://exslt.org/dynamic"
    xmlns:func="http://exslt.org/functions"
    xmlns:str="http://exslt.org/strings"
    extension-element-prefixes="dyn func str py">
  <xsl:output method="html"/>

  <!-- Try to use exslt:dynamic evaluate -->
  <xsl:template match="/">
    <html><body>
      <pre>
        <!-- Try dyn:evaluate -->
        <xsl:value-of select="dyn:evaluate('system-property(&quot;xsl:version&quot;)')"/>
        <!-- Show all system properties -->
        XSLT Version: <xsl:value-of select="system-property('xsl:version')"/>
        Vendor: <xsl:value-of select="system-property('xsl:vendor')"/>
        Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')"/>
      </pre>
    </body></html>
  </xsl:template>
</xsl:stylesheet>
