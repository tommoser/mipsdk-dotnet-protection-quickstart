﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;
using Microsoft.InformationProtection;
using System.Collections;
using System.ComponentModel;

namespace mipsdk_dotnet_protection_quickstart
{
    class Program
    {
        private static readonly string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static readonly string appName = ConfigurationManager.AppSettings["app:Name"];
        private static readonly string appVersion = ConfigurationManager.AppSettings["app:Version"];
        
        static void Main(string[] args)
        {
            // Create ApplicationInfo, setting the clientID from Azure AD App Registration as the ApplicationId
            // If any of these values are not set API throws BadInputException.
            ApplicationInfo appInfo = new ApplicationInfo()
            {
                // ApplicationId should ideally be set to the same ClientId found in the Azure AD App Registration.
                // This ensures that the clientID in AAD matches the AppId reported in AIP Analytics.
                ApplicationId = clientId,
                ApplicationName = appName,
                ApplicationVersion = appVersion
            };

            Console.WriteLine("Enter a user id: ");
            var userId = Console.ReadLine();

            // Initialize Action class, passing in AppInfo.
            Action action = new Action(appInfo, userId);
            
            var publishHandler = action.CreatePublishingHandler(userId);

            Console.WriteLine("Enter some string to protect: ");
            var userInputString = Console.ReadLine();
            var userInputBytes = Encoding.UTF8.GetBytes(userInputString);
            
            var encryptedBytes = action.Protect(publishHandler, userInputBytes);
            Console.WriteLine("");
            Console.WriteLine("Encrypted bytes (UTF8): {0}", Encoding.UTF8.GetString(encryptedBytes));
            Console.WriteLine("Encrypted bytes (base64): {0}", Convert.ToBase64String(encryptedBytes));
            Console.WriteLine("");

            var serializedPublishingLicense = publishHandler.GetSerializedPublishingLicense();

            var consumeHandler = action.CreateConsumptionHandler(serializedPublishingLicense);

            var decryptedBytes = action.Unprotect(consumeHandler, encryptedBytes);

            Console.WriteLine("Decrypted content: {0}", Encoding.UTF8.GetString(decryptedBytes));

            Console.WriteLine("Press a key to quit.");
            Console.ReadKey();
        }
    }
}
