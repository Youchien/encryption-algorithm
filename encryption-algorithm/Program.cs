using EncryptionAlgorithm.UtilityTools;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAlgorithm
{
    class Program
    {
        static void Main(string[] args)
        {
            
            String strOracleE = CryptographyUtilt.EncryptDES("Oracle");
            String strOracleD = CryptographyUtilt.DecryptDES("0QiAN7Xmnr8=");

            Debug.WriteLine("DES Encrypt >>>>>>>>>>>> " + strOracleE);
            Debug.WriteLine("DES Decrypt >>>>>>>>>>>> " + strOracleD);
        }
    }
}
