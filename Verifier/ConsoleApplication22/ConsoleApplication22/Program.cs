using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Net;
using System.Xml;
using System.Security.Cryptography.Xml;

namespace ConsoleApplication22
{
    class Program
    {

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
             var listener = new HttpListener();
            listener.Prefixes.Add("http://localhost:8091/");
            listener.Start();
            var ctx = listener.GetContext();

            using (var stream = new StreamReader(ctx.Request.InputStream))
            {
                var response = stream.ReadToEnd();
                var doc = new XmlDocument();
                doc.LoadXml(response);
                Console.WriteLine(Verify(doc) ? "SUCCESS!!" : "FAIL!!");
            }

            using (var resp = new StreamWriter(ctx.Response.OutputStream))
            {
                resp.Write(File.ReadAllText(@"C:\Mahmoud\Work\AppsWorthToSave\SigningXml\Signer\SigningXml\SignedXml.xml"));
                ctx.Response.ContentType = "application/soap+xml; charset=utf-8";
                resp.Close();
            }
            ctx.Response.OutputStream.Close();
            
            var doc1 = new XmlDocument();
            doc1.Load(@"C:\Mahmoud\Work\AppsWorthToSave\SigningXml\Signer\SigningXml\SignedXml.xml");
            Console.WriteLine(Verify(doc1) ? "SUCCESS!!" : "FAIL!!");
            Console.ReadLine();
        }

        private static bool Verify(XmlDocument doc)
        {
            SignedXmlWithId signedDoc = new SignedXmlWithId(doc);
            XmlNodeList nodeList = doc.GetElementsByTagName("Signature");

            signedDoc.LoadXml((XmlElement)nodeList[0]);
            return signedDoc.CheckSignature((RSA)Certificate.PublicKey.Key);
        }
    }

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
                nsManager.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

                idElem = doc.SelectSingleNode(string.Format("//*[@{0}:{1}=\"{2}\"]", "wsu", "Id", id), nsManager) as XmlElement;
            }

            return idElem;
        }
    }
}
