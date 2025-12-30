<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html"/>
  <xsl:template match="/">
    <html><body>
      <pre><xsl:copy-of select="document('http://127.0.0.1:5000/')"/></pre>
    </body></html>
  </xsl:template>
</xsl:stylesheet>
