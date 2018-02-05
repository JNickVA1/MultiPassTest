using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace CertinoMultipassLibrary
{
	/// <summary>
	/// The CertinoMultipass class creates the encrypted JSON message used to login to 
	/// Desk.com with Certino credentials, which will bypass the Desk.com login.
	/// </summary>
	public class CertinoMultipass
	{
		#region Fields
		/// <summary>
		/// The string that is used to identify the Desk support site.
		/// </summary>
		/// <remarks>
		/// In our case, the site is certino.desk.com, so the site key is "certino".
		/// </remarks>
		public const string SiteKey = @"certino";

		/// <summary>
		/// The API key generated at https://certino.desk.com/admin/channels/support-center/auth_settings. 
		/// </summary>
		/// <remarks>
		/// The API key must be edited here anytime it is re-generated in the Private Access settings at the URL above.
		/// NOTE: I have opted to use a constant for the time being instead of a property or setting.
		/// </remarks>
		private const string ApiKey = "9aa1cf42a06d571c2cd43a7a02b970efa0483d10";
		#endregion Fields

		#region Constructors
		/// <summary>
		/// 
		/// </summary>
		/// <param name="userId">The unique identifier of the user.</param>
		/// <param name="minutes">The number of minutes that the Multipass is valid, from Now().
		///     Multipass expiration date is in ISO 8601 format, so we must perform a conversion.</param>
		/// <param name="userEmail">Customer's email address.</param>
		/// <param name="userName">Customer's name.</param>
		/// <param name="navigateTo">Absolute URL to redirect the user after successful login. 
		/// If this is not supplied, users are either redirected to the original page they were 
		/// viewing/attempting to view on your portal, or they are redirected to your portal's home.</param>
		/// <param name="userCustomKey">The custom customer field identified by the key.</param>
		public CertinoMultipass(string userId, int minutes, string userEmail, string userName, string navigateTo = "", string userCustomKey = "")
		{
			// Assign all parameter values to the instance properties.
			UserId = userId;
			Minutes = minutes;
			UserEmail = userEmail;
			UserName = userName;
			// NOTE: NavigateTo is currently unused.
			NavigateTo = navigateTo;
			// NOTE: UserCustomKey is currently unused.
			UserCustomKey = userCustomKey;
		}
		#endregion Constructors

		#region Properties
		/// <summary>
		/// See comment in constructor.
		/// </summary>
		public string UserId { get; set; }

		/// <summary>
		/// See comment in constructor.
		/// </summary>
		public int Minutes { get; set; }

		/// <summary>
		/// See comment in constructor.
		/// </summary>
		public string UserEmail { get; set; }

		/// <summary>
		/// See comment in constructor.
		/// </summary>
		public string UserName { get; set; }

		/// <summary>
		/// See comment in constructor.
		/// </summary>
		public string NavigateTo { get; set; }

		/// <summary>
		/// See comment in constructor.
		/// </summary>
		public string UserCustomKey { get; set; }

		/// <summary>
		/// Returns the URL to which the user will be transferred on Desk.com
		/// </summary>
		/// <remarks>
		/// The URL string contains the encrypted Multipass SSO authentication.
		/// </remarks>
		public string UserMultipassToken
		{
			get
			{
				try
				{
					// Serialize a Dictionary object that contains the key/value pairs required for Multipass.
					// TODO: Add the capability for including optional keys and values.
					var json = JsonConvert.SerializeObject(new Dictionary<string, string>(){
						{"uid", UserId},
						{"expires", DateTime.UtcNow.AddMinutes(Minutes).ToString("o")},
						{"customer_email", UserEmail},
						{"customer_name", UserName}
					});
					// The URL string to be constructed and returned.
					string urlAtDesk;

					// Using a new instance of the AesManaged class, construct 
					// the various parts of the encrypted Multipass token.
					using (var myAes = new AesManaged())
					{
						//
						var encrypted = Encrypt(json, EncryptionKey(), myAes.IV);

						//
						var combined = new byte[myAes.IV.Length + encrypted.Length];

						//
						Array.Copy(myAes.IV, 0, combined, 0, myAes.IV.Length);

						//
						Array.Copy(encrypted, 0, combined, myAes.IV.Length, encrypted.Length);

						//
						var multipass = Convert.ToBase64String(combined);

						//
						var encryptedSignature = Signature(multipass);

						//
						var signature = Convert.ToBase64String(encryptedSignature);

						//
						multipass = Uri.EscapeDataString(multipass);

						//
						signature = Uri.EscapeDataString(signature);

						//
						urlAtDesk =
							$"https://{SiteKey}.desk.com/customer/authentication/multipass/callback?multipass={multipass}&signature={signature}";
						// https://Certino.desk.com/customer/authentication/multipass/callback?multipass=48yu1Q%2FWcvfmNalNcSFqdpwfxLW86G806zd2WgGwBhqeWem%2BxWgHrCNKOsn5JXIp%2FXmHxQQ91qSVf2CLocdD0qABl8SdaBahp5zp4375ccNGB%2Fdf7q2QVZIhs%2FFc%2ButKNnt2ZZGWLDDI9qeHJJjdUKiBYWTp9SmKdgkXeQ%2BtR4Y%2B1%2F5gFmjYOur3fM17%2FMyzjRVvJThc29xYZ2A78jAzavbsPNjuynR3WZfK9hBUoefHcVTS8bpBmmWuS3gjhwwn&signature=ldOj8iNkLUbJKPqCwwKVYYHh%2B%2F4%3D
					}
					return urlAtDesk;
				}
				catch (Exception e)
				{
					throw new ApplicationException("Error constructing Multipass token.", e);
				}
			}
		}
		#endregion Properties

		#region Methods
		/// <summary>
		/// Creates a symmetric encryptor using the supplied key and initialization vector,
		/// uses that encryptor to transform the supplied JSON string, and then returns the
		/// encrypted stream as a byte array.
		/// </summary>
		/// <param name="json"></param>
		/// <param name="key"></param>
		/// <param name="iv"></param>
		/// <returns>The encrypted data as a byte array.</returns>
		private static byte[] Encrypt(string json, byte[] key, byte[] iv)

		{
			// The byte array that will be returned.
			byte[] encrypted;

			// Use an instance of AesManaged to create the encryptor.
			using (var aesAlg = new AesManaged())
			{
				// Use the supplied key and
				aesAlg.Key = key;

				// the IV byte array to 
				aesAlg.IV = iv;

				// create an encryptor to perform the stream transform.
				var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

				// Create a MemoryStream to use as the destination of the encryption.
				using (var msEncrypt = new MemoryStream())
				{
					// Create an instance of the CryptoStream to transform the data (the JSON package).
					using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
					{
						// Now, create an instance of StreamWriter to wrap the encrypted data.
						using (var swEncrypt = new StreamWriter(csEncrypt))
						{
							// Using all of the mentioned class objects, write the encrypted data to the stream.
							swEncrypt.Write(json);
						}
						// Finally, extract the encrypted data from the MemoryStream as a byte array.
						encrypted = msEncrypt.ToArray();
					}
				}
			}
			return encrypted;
		}

		/// <summary>
		/// Creates and returns a byte array that represents the hash value 
		/// for a 'salt' created by combining the ApiKey and the SiteKey.
		/// </summary>
		/// <returns>A byte array representing the hash value used as an encryption key.</returns>
		private static byte[] EncryptionKey()
		{
			// The byte array that will be returned.
			byte[] key;

			// Encode the combined string in UTF8 format and retrieve the byte array of the sequence.
			var salt = Encoding.UTF8.GetBytes(ApiKey + SiteKey);

			// Create the object used to compute the hash value.
			using (SHA1 sha1 = new SHA1CryptoServiceProvider())
			{
				// Compute the hash value for the "salt" byte array.
				key = sha1.ComputeHash(salt);

				// Resize the hash value to an array of length 16.
				Array.Resize(ref key, 16);
			}
			return key;
		}

		/// <summary>
		/// Compute the hash value used to "sign" the Multipass package.
		/// </summary>
		/// <param name="multipass"></param>
		/// <returns>A byte array representing the hash value used as a signature.</returns>
		private static byte[] Signature(string multipass)
		{
			// The byte array that will be returned.
			byte[] signature;

			// Compute a HMAC using the UTF8 format of the API key as a byte array.
			using (var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(ApiKey)))
			{
				// Create a MemoryStream to use as the destination of the computed hash value.
				using (var msHmac = new MemoryStream(Encoding.UTF8.GetBytes(multipass)))
				{
					// Call the HMAC method to compute the hash as a byte array.
					signature = hmac.ComputeHash(msHmac);
				}
			}
			return signature;
		}
		#endregion Methods

		#region Event Handlers
		#endregion Event Handlers
	}
}
