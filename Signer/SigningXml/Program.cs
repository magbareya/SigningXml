using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Xml;
using System.Net;

namespace XmlFileSigner
{
    class Program
    {
        private const string OriginalXml = @"../../Xml2Sign.xml";
        private const string SignedXml = @"../../SignedXml.xml";

        private static X509Certificate2 cert;
        private static X509Certificate2 Certificate
        {
            get
            {
                if (cert == null)
                {
                    X509Store store = new X509Store("My", StoreLocation.CurrentUser);
                    store.Open(OpenFlags.ReadOnly);
                    cert = store.Certificates[52];
                    store.Close();
                }
                return cert;
            }
        }

        static void Main(string[] args)
        {
            XmlDocument signedDoc = SignXml();
            
            File.WriteAllText(SignedXml, signedDoc.OuterXml);
            /*
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(File.ReadAllText(SignedXml));//.Replace(Common.SOAP11Namespace, Common.SOAP12Namespace));

            SignatureVerifier ver = new SignatureVerifier(doc);
            if(ver.VerifyXml((RSA)Certificate.PublicKey.Key))
                Console.WriteLine("GOOD");
            else Console.WriteLine("BAD");
            Console.ReadLine();
            //SendRequest(doc.OuterXml);
            return;*/
        }

        private static void SendRequest(string p)
        {
            HttpWebRequest request = WebRequest.Create("http://localhost:8091") as HttpWebRequest;
            request.Method = "POST";
            StreamWriter requestStr = new StreamWriter(request.GetRequestStream());
            requestStr.Write(p);
            requestStr.Flush();
            requestStr.Close();
            request.GetResponse();
        }

        private static XmlDocument SignXml()
        {
            XmlDocument doc2Sign = new XmlDocument();
            doc2Sign.LoadXml(File.ReadAllText(OriginalXml));
            
            string Id = AddBinaryToken(Certificate.GetRawCertData(),doc2Sign);

            XmlSigner signer = new XmlSigner(doc2Sign);

            List<string> xpathsToSign = new List<string>();
            xpathsToSign.Add(Common.BodyXPath);

            XmlDocument ret = signer.SignXml((RSA)Certificate.PrivateKey, xpathsToSign, Id);

            return ret;
        }

        private static string AddBinaryToken(byte[] certData, XmlDocument doc)
        {
            string id = Common.GetUniqueID();
            XmlNode bst = Common.CreateSecurityChild(Common.BinarySecurityTokenElement, doc);

            //add ValueType attribute
            XmlAttribute valueType = doc.CreateAttribute(Common.ValueTypeAttribute);
            valueType.AppendChild(doc.CreateTextNode(Common.ValueTypeValue));
            bst.Attributes.Append(valueType);

            //add EncodingType
            XmlAttribute encodingType = doc.CreateAttribute(Common.EncodingTypeAttribute);
            encodingType.AppendChild(doc.CreateTextNode(Common.EncodingTypeValue));
            bst.Attributes.Append(encodingType);

            //add id attribute
            XmlAttribute idAtt = Common.CreateSecurityUtilityAttribute(Common.IdAttribute, doc);
            idAtt.AppendChild(doc.CreateTextNode(id));
            bst.Attributes.Append(idAtt);

            //add value of the element
            bst.AppendChild(doc.CreateTextNode(Convert.ToBase64String(certData)));

            //append the element to the document under Security element
            XmlNode security = Common.GetSecurityElement(doc);
            security.InsertBefore(bst, security.FirstChild);
            return id;
        }
    }
}
