using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Security.Cryptography.X509Certificates;

namespace XmlFileSigner
{
    class SignatureVerifier
    {

        #region properties
        private XmlDocument xmlToVerify;

        public XmlDocument XmlToVerify
        {
            get { return this.xmlToVerify; }
            set { this.xmlToVerify = value; }
        }

        #endregion

        #region Constructors
        public SignatureVerifier(string xmlStr)
        {
            this.XmlToVerify = GetXmlFromString(xmlStr);
        }

        public SignatureVerifier(XmlDocument xmlDoc)
        {
            this.XmlToVerify = xmlDoc;
        }

        private XmlDocument GetXmlFromString(string xml)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(xml);

            return doc;
        }
        #endregion


        public bool VerifyXml(RSA key)
        {
            SignedXmlWithId signedXml = new SignedXmlWithId(this.XmlToVerify);
            XmlNodeList nodeList = this.XmlToVerify.GetElementsByTagName(Common.SignatureElement);

            signedXml.LoadXml((XmlElement)nodeList[0]);

            return signedXml.CheckSignature(key);
        }

        public bool VerifyXml()
        {
            X509Certificate2 cert = Common.ReadBinaryToken(this.XmlToVerify);
            return this.VerifyXml((RSA)cert.PublicKey.Key);
        }
    }
}
