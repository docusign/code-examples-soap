using System;
//using System.Windows.Forms;
using AuthoritativeCopySOAPExample.DocuSignSoapApi;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;

//Example code demonstrates how to:
//1. Export the authoritative copies of the documents of a given envelope.
//2. Acknowledge receipt of the authoritative copies
//3. Decrypt the documents with the returned key

//Methods:
// AuthCopyFlow(string envelopeId)

//  Exports and acknowledges the Authoritative copy documents. Then calls decrypt() to write the decrypted files.
//  Once exported you cannot call DSAPIServiceSoapClient.ExportAuthoritativeCopy() again. 

// Decrypt(string exportKey, string inputFile, string outputFile)

//  Decrypts inputFile using the exportKey and writes decrypted pdf to outputFile

//Note hard coded file paths for target encrypted and decrypted files.
//This example does not include the steps of moving decrypted files to your vault or cleaning up temp file.
//Your application will need to add intelligence to the file naming and storage scheme.

namespace AuthoritativeCopySOAPExample
{
    class Program
    {
        static void Main(string[] args)
        {
            //Call with envelopeId
            AuthCopyFlow("3f7dbae1-xxxx-xxxx-xxxx-b0e222587c3");

        }

        public static void AuthCopyFlow(string envelopeId)
        {
            //Configure these variables for your environment
            string userName = "";
            string password = "";
            string integratorKey = "";
            string accountId = "";    //Use a GUID example db7f5b2a-xxxx-xxxx-xxxx-a815685a63eb


            //OAuth is not yet supported by DocuSign SOAP API
            //Authentication can be either WS-Security UsernameToken or Legacy custom header authentication, 
            //although some development stacks may not provide adequate support for WS-Security standards.  

            String auth = "<DocuSignCredentials><Username>" + userName
            + "</Username><Password>" + password
            + "</Password><IntegratorKey>" + integratorKey
            + "</IntegratorKey></DocuSignCredentials>";

            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;

            DSAPIServiceSoapClient client = new DSAPIServiceSoapClient();


            using (OperationContextScope scope = new System.ServiceModel.OperationContextScope(client.InnerChannel))
            {
                HttpRequestMessageProperty httpRequestProperty = new HttpRequestMessageProperty();
                httpRequestProperty.Headers.Add("X-DocuSign-Authentication", auth);
                OperationContext.Current.OutgoingMessageProperties[HttpRequestMessageProperty.Name] = httpRequestProperty;


                if (envelopeId.Trim().Length != 36)
                {
                    Console.WriteLine("Error: EnvelopeId should be 36 characters. Current is " + envelopeId.Trim().Length.ToString());
                    Console.ReadLine();
                    return;
                }

                try
                {
                    AuthoritativeCopyExportDocuments docs = client.ExportAuthoritativeCopy(envelopeId);

                    //Concatenate the byte arrays of the returned encrypted documents
                    var s = new MemoryStream();
                    List<string> encryptedFiles = new List<string>();

                    for (int i = 0; i < docs.Count; i++)
                    {
                        byte[] docPDF = docs.DocumentPDF[i].PDFBytes;
                        s.Write(docPDF, 0, docPDF.Length);

                        //write encrypted file to use later
                        encryptedFiles.Add(@"c:\temp\authcopy\Testdoc.dat" + i.ToString());
                        File.WriteAllBytes(@"c:\temp\authcopy\Testdoc.dat" + i.ToString(), docPDF);

                    }

                    //Write the concatenated memory stream to the concatenatedByteArray
                    var concatenatedByteArray = s.ToArray();
                    int size = concatenatedByteArray.Length;
                        
                    //Create a new fixed byte array required to hash
                    byte[] data = new byte[size];
                    data = concatenatedByteArray;

                    System.Security.Cryptography.SHA1 sha = new SHA1CryptoServiceProvider();

                    byte[] computedHash;
                    computedHash = sha.ComputeHash(data);

                    AuthoritativeCopyExportStatus status = client.AcknowledgeAuthoritativeCopyExport(envelopeId.Trim(), docs.TransactionId, computedHash);
                    string key = status.ExportKey;

                    Console.WriteLine("Status = " + status.AuthoritativeCopyExportSuccess + "Key = " + key);

                    // loop writing decrypted docs to files
                    for (int i = 0; i < docs.Count; i++)
                    {
                        //Create an empty target file
                        string decryptedFilename = @"c:\temp\authcopy\" + docs.DocumentPDF[i].Name;

                        if(decryptedFilename == @"c:\temp\authcopy\Summary")
                        {
                            decryptedFilename = @"c:\temp\authcopy\Summary.pdf";
                        }

                        File.Create(decryptedFilename).Dispose();

                        //Decrypte the file using the key that was returned from AcknowledgeAuthoritativeCopyExport()
                        try
                        {
                            Decrypt(status.ExportKey, encryptedFiles[i], decryptedFilename);
                            Console.WriteLine("Success: new file " + decryptedFilename);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("Decrypt and file write failed.");
                            Console.WriteLine(ex.Message);
                        }                            
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }                   
 
            }

            Console.ReadLine();
        }

        public static void Decrypt(string exportKey, string inputFile, string outputFile)
        {
            try
            {
                byte[] exportKeyBytes = System.Text.Encoding.UTF8.GetBytes(exportKey);
                byte[] ivBytes = new byte[exportKey.Length];
                Array.Copy(exportKeyBytes, ivBytes, exportKey.Length);

                RijndaelManaged RMCrypto = new RijndaelManaged();
                RMCrypto.Mode = CipherMode.CBC;
                RMCrypto.Padding = PaddingMode.PKCS7;
                RMCrypto.KeySize = 128;
                RMCrypto.BlockSize = 128;

                ICryptoTransform transform = RMCrypto.CreateDecryptor(exportKeyBytes, ivBytes);

                FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
                CryptoStream cs = new CryptoStream(fsCrypt, transform, CryptoStreamMode.Read);

                FileStream fsOut = new FileStream(outputFile, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);

                int data;
                while ((data = cs.ReadByte()) != -1)
                    fsOut.WriteByte((byte)data);

                fsOut.Close();
                cs.Close();
                fsCrypt.Close();

            }
            catch (Exception ex)
            {
                throw (ex);
            }
        }
    }
}
