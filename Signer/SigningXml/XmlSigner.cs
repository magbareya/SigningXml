using System;
using System.Collections.Generic;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace XmlFileSigner
{
    class XmlSigner
    {
        #region properties
        private XmlDocument xmlToSign;

        public XmlDocument XmlToSign
        {
            get { return this.xmlToSign; }
            set { this.xmlToSign = value; }
        }

        #endregion

        #region Constructors
        public XmlSigner(string xmlToSignStr)
        {
            this.XmlToSign = GetXmlFromString(xmlToSignStr);
        }

        public XmlSigner(XmlDocument xmlToSignDoc)
        {
            this.XmlToSign = xmlToSignDoc;
        }

        private XmlDocument GetXmlFromString(string xml)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xml);

            return doc;
        }
        #endregion

        /// <summary>
        /// Sign the xml that was passed in the constructor (I assume that it is SOAP)
        /// A <Signature> element will be added to the SOAP with XPath: Envelope/Header/Security/Signature
        /// </summary>
        /// <param name="key">the key to be used to sign the elements (Certificate.PrivateKey)</param>
        /// <param name="xpathsToSign">the xpaths of the elements you want to be signed in the soap</param>
        /// <returns></returns>
        public XmlDocument SignXml(RSA key, IEnumerable<string> xpathsToSign, string tokenId)
        {
            return SignXml(key, AddIdToElements(xpathsToSign), tokenId);
        }

        public XmlDocument SignXml(RSA key, IEnumerable<Microsoft.Web.Services2.Security.SignatureReference> references, string tokenId )
        {
            List<Reference> newRefs = new List<Reference>();
            foreach(Microsoft.Web.Services2.Security.SignatureReference r in references)
            {
                newRefs.Add(Common.GetReference(r));
            }
            return SignXml(key, newRefs, tokenId);
        }

        public XmlDocument SignXml(RSA key, IEnumerable<Reference> references, string tokenId)
        {
            SignedXmlWithId signedxml = new SignedXmlWithId(this.XmlToSign);

            if(references == null)
                throw new ArgumentNullException("references");
            
            foreach (Reference r in references)
                    signedxml.AddReference(r);

            signedxml.SigningKey = key;

            SetAlgorithms(signedxml);

            signedxml.KeyInfo.AddClause(new KeyInfoNode(GetTokenReferenceElement(tokenId)));

            signedxml.ComputeSignature();

            XmlElement signatureElem = signedxml.GetXml();

            AddSignatureElement(signatureElem);

            return this.XmlToSign;
        }

        private XmlElement GetTokenReferenceElement(string id)
        {
            //create <SecurityTokenReference> element
            XmlNode str = Common.CreateSecurityChild(Common.SecurityTokenReferenceElement, this.XmlToSign);

            //create <Reference> element
            XmlNode reference = Common.CreateSecurityChild(Common.ReferenceElement, this.XmlToSign);

            //create URI attribute
            XmlAttribute uriAtt = this.XmlToSign.CreateAttribute(Common.URIAttribute);
            uriAtt.AppendChild(this.XmlToSign.CreateTextNode(string.Format("#{0}", id)));
            reference.Attributes.Append(uriAtt);

            //add ValueType attribute
            XmlAttribute valueType = this.XmlToSign.CreateAttribute(Common.ValueTypeAttribute);
            valueType.AppendChild(this.XmlToSign.CreateTextNode(Common.ValueTypeValue));
            reference.Attributes.Append(valueType);

            str.AppendChild(reference);

            return str as XmlElement;
        }

        #region Private functions
        private void SetAlgorithms(SignedXml signedXml)
        {
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            XmlDsigExcC14NTransform canMethod = (XmlDsigExcC14NTransform)signedXml.SignedInfo.CanonicalizationMethodObject;
        }

        private void AddSignatureElement(XmlElement signatureElem)
        {
            XmlNode security = Common.GetSecurityElement(this.XmlToSign);
            security.AppendChild(signatureElem);
        }

        private IEnumerable<Reference> AddIdToElements(IEnumerable<string> xpaths)
        {
            List<Reference> refList = new List<Reference>();

            foreach(string xp in xpaths)
            {
                XmlNode element = this.XmlToSign.SelectSingleNode(xp);
                XmlAttribute idAtt = Common.CreateSecurityUtilityAttribute(Common.IdAttribute, this.XmlToSign);
                 
                string id = Common.GetUniqueID();
                idAtt.AppendChild(this.XmlToSign.CreateTextNode(id));
                element.Attributes.Append(idAtt);
                
                refList.Add(GetReference(id));
            }
            return refList;
        }
        


        private static Reference GetReference(string id)
        {
            Reference reference = new Reference(string.Format("#{0}", id));
            XmlDsigExcC14NTransform env = new XmlDsigExcC14NTransform();
            reference.AddTransform(env);
            return reference;
        }
        /*
        private void AddTokenReference(string id)
        {
            XmlNode signature = this.XmlToSign.GetElementsByTagName(Common.SignatureElement)[0];

            //create <KeyInfo> element
            XmlNode keyInfo = this.XmlToSign.CreateElement(signature.Prefix, Common.KeyInfoElement,
                                                           signature.NamespaceURI);

            //create <SecurityTokenReference> element
            XmlNode str = Common.CreateSecurityChild(Common.SecurityTokenReferenceElement, this.XmlToSign);

            //create <Reference> element
            XmlNode reference = Common.CreateSecurityChild(Common.ReferenceElement, this.XmlToSign);

            //create URI attribute
            XmlAttribute uriAtt = this.XmlToSign.CreateAttribute(Common.URIAttribute);
            uriAtt.AppendChild(this.XmlToSign.CreateTextNode(string.Format("#{0}", id)));
            reference.Attributes.Append(uriAtt);

            //add ValueType attribute
            XmlAttribute valueType = this.XmlToSign.CreateAttribute(Common.ValueTypeAttribute);
            valueType.AppendChild(this.XmlToSign.CreateTextNode(Common.ValueTypeValue));
            reference.Attributes.Append(valueType);

            //append children
            str.AppendChild(reference);
            keyInfo.AppendChild(str);
            signature.AppendChild(keyInfo);
        }*/


        #endregion
    }
}
