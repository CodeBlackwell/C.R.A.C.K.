<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <!-- Import a non-XSLT file - error should reveal contents -->
  <xsl:import href="../app.py"/>
  <xsl:template match="/">
    <html><body>test</body></html>
  </xsl:template>
</xsl:stylesheet>
