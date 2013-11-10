using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace XmlFileSigner
{
    public class SignedXmlWithId : SignedXml
    {
        public SignedXmlWithId(XmlDocument xml)
            : base(xml)
        {
        }

        public SignedXmlWithId(XmlElement xmlElement)
            : base(xmlElement)
        {
        }

        public override XmlElement GetIdElement(XmlDocument doc, string id)
        {
            // check to see if it's a standard ID reference
            XmlElement idElem = base.GetIdElement(doc, id);

            if (idElem == null)
            {
                XmlNamespaceManager nsManager = new XmlNamespaceManager(doc.NameTable);
                nsManager.AddNamespace(Common.SecurityUtilityPrefix, Common.SecurityUtilityNamespace);

                idElem = doc.SelectSingleNode(string.Format("//*[@{0}:{1}=\"{2}\"]", Common.SecurityUtilityPrefix, Common.IdAttribute, id), nsManager) as XmlElement;
            }

            return idElem;
        }
    }
}
