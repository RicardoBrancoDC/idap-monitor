import datetime as dt
import unittest
import xml.etree.ElementTree as ET

import app


class ParserTests(unittest.TestCase):
    def test_operational_id_ignores_feed_url(self):
        xml = """
        <root>
          <id>http://idapapi.mi.gov.br/api/rss/cap</id>
          <entry><id>100008/2022</id></entry>
        </root>
        """
        root = ET.fromstring(xml)
        self.assertEqual(app.extract_alert_id(root), "100008/2022")

    def test_sender_name_is_institution(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
          <id>100008/2022</id>
          <identifier>TESTE</identifier>
          <sender>codigo-tecnico</sender>
          <sent>2026-09-14T10:00:00-03:00</sent>
          <info>
            <language>pt-BR</language>
            <senderName>Defesa Civil de Teste</senderName>
            <event>Chuva intensa</event>
            <urgency>Expected</urgency>
            <severity>Moderate</severity>
            <certainty>Likely</certainty>
            <effective>2026-09-14T10:00:00-03:00</effective>
            <expires>2026-09-14T12:00:00-03:00</expires>
            <headline>Risco de chuva intensa. Evite áreas alagadas.</headline>
          </info>
        </alert>""".encode("utf-8")
        result = app.parse_cap(
            "10000814092026-SP.xml",
            "https://idapcap.mdr.gov.br/10000814092026-SP.xml",
            dt.date(2026, 9, 14),
            "SP",
            xml,
        )
        self.assertEqual(result["alert_id"], "100008/2022")
        self.assertEqual(result["sender"], "codigo-tecnico")
        self.assertEqual(result["sender_name"], "Defesa Civil de Teste")
        self.assertEqual(result["institution"], "Defesa Civil de Teste")


if __name__ == "__main__":
    unittest.main()
