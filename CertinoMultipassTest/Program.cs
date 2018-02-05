using System;
using System.Diagnostics;
using CertinoMultipassLibrary;

namespace CertinoMultipassTest
{
	class Program
	{
		static void Main(string[] args)
		{
			try
			{
				// Create the object that will encode the Multipass.
				var multipassGenerator = new CertinoMultipass("123456789", 60, "james.nicholson@certino.com", "James Nicholson");

				// Retrieve the completely encoded Multipass-enabled URL used to transfer the user to Desk.com.
				var urlAtDesk = multipassGenerator.UserMultipassToken;
				// https://certino.desk.com/customer/authentication/multipass/callback?multipass=6kzP9%2FX1vyCXpQ4ubXozew1yhsQPdugTCo7MzKYU4QNT%2ByUJqNxQqJot2lTvp%2FB4WtOlv5iFG5dEcTJtj5B4X6zo1GDpNhGRl7K2z9XY5MgykIWyFCGigoM9rohsYfTZYf06W0Nbu7INUJZZGlsc8KhxTzXbfU%2FzWdTDI1s5FSSZzNwv44Fb0h1GAN2%2B6uhSKt3WEZHre3fdL3qFcPnvcA%3D%3D&signature=kL4I24B0n13My3KLu45YqN9nKVU%3D
				Debug.WriteLine(urlAtDesk);
			}
			catch (Exception e)
			{
				// Handle any errors.
			}
		}

		#region Methods
		#endregion Methods
	}
}
