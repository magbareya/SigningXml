using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace XmlFileSigner
{
    class Common
    {

        #region Constant Strings
        internal const string SecurityUtilityNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
        internal const string SecurityNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        internal const string SignatureNamespace = "http://www.w3.org/2000/09/xmldsig#";
        internal const string SOAP11Namespace = "http://schemas.xmlsoap.org/soap/envelope/";
        internal const string SOAP12Namespace = "http://www.w3.org/2003/05/soap-envelope";
        internal const string WsAddressingNamespace = "http://schemas.xmlsoap.org/ws/2004/03/addressing";

        internal const string SecurityUtilityPrefix = "wsu";
        internal const string SecurityPrefix = "wsse";
        internal const string WSAPrefix = "wsa";

        internal const string IdAttribute = "Id";
        internal const string URIAttribute = "URI";
        internal const string ValueTypeAttribute = "ValueType";
        internal const string EncodingTypeAttribute = "EncodingType";


        internal const string ValueTypeValue =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";

        internal const string EncodingTypeValue =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";


        internal const string HeaderElement = "Header";
        internal const string SecurityElement = "Security";
        internal const string SignatureElement = "Signature";
        internal const string KeyInfoElement = "KeyInfo";
        internal const string BinarySecurityTokenElement = "BinarySecurityToken";
        internal const string SecurityTokenReferenceElement = "SecurityTokenReference";
        internal const string ReferenceElement = "Reference";

        internal const string EnvelopeXPath = "/*[local-name(.)='Envelope']";
        internal static string BodyXPath = String.Format("{0}/*[local-name(.)='Body']", EnvelopeXPath);
        internal static string HeaderXPath = String.Format("{0}/*[local-name(.)='Header']", EnvelopeXPath);
        internal static string SecurityXPath = String.Format("{0}/*[local-name(.)='Security']", HeaderXPath);
        internal static string BinarySecurityTokenXPath = String.Format("{0}/*[local-name(.)='BinarySecurityToken']", SecurityXPath);
        internal static string SignatureXPath = String.Format("{0}/*[local-name(.)='Signature']", SecurityXPath);
        internal static string KeyInfoXPath = String.Format("{0}/*[local-name(.)='KeyInfo']", SignatureXPath);
        internal static string SecurityTokenReferenceXPath = String.Format("{0}/*[local-name(.)='SecurityTokenReference']", KeyInfoXPath);
        internal static string KeyInfoReferenceXPath = String.Format("{0}/*[local-name(.)='Reference']", SecurityTokenReferenceXPath);
        internal static string ActionXPath = String.Format("{0}/*[local-name(.)='Action']", HeaderXPath);
        internal static string MessageIdXPath = String.Format("{0}/*[local-name(.)='MessageID']", HeaderXPath);
        internal static string ReplyToXPath = String.Format("{0}/*[local-name(.)='ReplyTo']", HeaderXPath);
        internal static string ToXPath = String.Format("{0}/*[local-name(.)='To']", HeaderXPath);
        internal static string TimestampXPath = String.Format("{0}/*[local-name(.)='Timestamp']", SecurityXPath);

        #endregion

        #region Static Methods

        internal static string GetUniqueID()
        {
            return Guid.NewGuid().ToString().Replace("-", String.Empty);
        }

        internal static XmlNode GetSecurityElement(XmlDocument doc)
        {
            XmlNode env = doc.SelectSingleNode(EnvelopeXPath);
            XmlNode header = doc.SelectSingleNode(HeaderXPath);
            if (header == null)
            {
                header = doc.CreateElement(env.Prefix, HeaderElement, env.NamespaceURI);
                env.InsertBefore(header, env.FirstChild);
            }

            XmlNode security = doc.SelectSingleNode(SecurityXPath);
            if (security == null)
            {
                security = CreateSecurityUtilityChild(SecurityElement, doc);
                header.AppendChild(security);
            }

            return security;
        }

        internal static X509Certificate2 ReadBinaryToken(XmlDocument doc)
        {
            XmlNode reference = doc.SelectSingleNode(KeyInfoReferenceXPath);
            string id = reference.Attributes[string.Format("{0}:{1}", SecurityUtilityPrefix, URIAttribute)].Value;
            return ReadBinaryToken(doc, id);
        }

        internal static X509Certificate2 ReadBinaryToken(XmlDocument doc, string id)
        {
            if (id.StartsWith("#"))
                id = id.Substring(1);
            XmlNodeList bsts = doc.SelectNodes(BinarySecurityTokenXPath);

            XmlNode bst = null;
            foreach (XmlNode n in bsts)
            {
                XmlAttribute idAtt = n.Attributes[string.Format("{0}:{1}", SecurityUtilityPrefix, IdAttribute)];
                if (idAtt != null && idAtt.Value.Equals(id))
                {
                    bst = n;
                    break;
                }
            }

            return (bst != null) ? new X509Certificate2(Convert.FromBase64String(bst.FirstChild.Value)) : null;
        }

        internal static Reference GetReference(string id)
        {
            Reference reference = new Reference(string.Format("#{0}", id));
            reference.AddTransform(GetTransform());
            return reference;
        }

        internal static Reference GetReference(Microsoft.Web.Services2.Security.SignatureReference reference)
        {
            Reference newr = new Reference(reference.Uri);
            newr.AddTransform(GetTransform());
            return newr;
        }

        private static Transform GetTransform()
        {
            return new XmlDsigExcC14NTransform();
        }

        internal static XmlNode CreateSecurityUtilityChild(string name, XmlDocument doc)
        {
            return doc.CreateElement(SecurityUtilityPrefix, name, SecurityUtilityNamespace);
        }

        internal static XmlAttribute CreateSecurityUtilityAttribute(string name, XmlDocument doc)
        {
            return doc.CreateAttribute(SecurityUtilityPrefix, name, SecurityUtilityNamespace);
        }

        internal static XmlNode CreateSecurityChild(string name, XmlDocument doc)
        {
            return doc.CreateElement(SecurityPrefix, name, SecurityNamespace);
        }

        internal static XmlAttribute CreateSecurityAttribute(string name, XmlDocument doc)
        {
            return doc.CreateAttribute(SecurityPrefix, name, SecurityNamespace);
        }

        #endregion
    
    }
}
