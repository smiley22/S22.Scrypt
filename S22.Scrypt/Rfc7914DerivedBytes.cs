using System;
using System.Security.Cryptography;

namespace S22.Scrypt {
	/// <summary>
	/// Implements the password-based key derivation function scrypt.
	/// </summary>
	public class Rfc7914DerivedBytes : DeriveBytes {
		/// <summary>
		/// Gets or sets the key salt value for the operation.
		/// </summary>
		/// <exception cref="ArgumentNullException">
		/// The property is being set and the new salt value is null.
		/// </exception>
		/// <remarks>
		/// Salt, a random set of bytes, is used to make unauthorized decrypting of a message more
		/// difficult. A dictionary attack is an attack in which the attacker attempts to decrypt
		/// an encrypted message by comparing the encrypted value with previously computed
		/// encrypted values for the most likely keys. This attack is made much more difficult by
		/// the introduction of salt, or random bytes, at the end of the password before the key
		/// derivation.
		/// </remarks>
		public byte[] Salt {
			get;
			set;
		}

		/// <summary>
		/// Gets or sets the block size parameter for the operation.
		/// </summary>
		/// <remarks>
		/// At the current time (August 2016), a block size of 8 appears to yield good results.
		/// </remarks>
		public int BlockSize {
			get;
			set;
		}

		/// <summary>
		/// Gets or sets the CPU/Memory cost parameter for the operation.
		/// </summary>
		/// <remarks>
		/// The CPU/Memory cost parameter must be larger than 1, a power of 2, and less than
		/// 2^(128 * <see cref="BlockSize"/> / 8).
		/// </remarks>
		/// <exception cref="ArgumentException">
		/// The property is being set and the new value is less than or equal to 1, or the new
		/// value is not a power of 2, or the new value is less then
		/// 2^(128 * <see cref="BlockSize"/> / 8).
		/// </exception>
		public int Cost {
			get;
			set;
		}

		/// <summary>
		/// Gets or sets the Parallelization parameter for the operation.
		/// </summary>
		/// <remarks>
		/// The parallelization parameter is a positive integer less than or equal to
		/// ((2^32-1) * 32) / (128 * <see cref="BlockSize"/>).
		/// </remarks>
		/// <exception cref="ArgumentException">
		/// The property is being set and the new value is negative, or the new value is bigger
		/// than ((2^32-1) * 32) / (128 * <see cref="BlockSize"/>).
		/// </exception>
		public int Parallelization {
			get;
			set;
		}

		/// <summary>
		/// Returns the pseudo-random key for this object.
		/// </summary>
		/// <param name="cb">
		/// The number of pseudo-random key bytes to generate.
		/// </param>
		/// <returns>
		/// A byte array filled with pseudo-random key bytes.
		/// </returns>
		/// <exception cref="ArgumentOutOfRangeException">
		/// The cb parameter is out of range. This parameter requires a non-negative number.
		/// </exception>
		/// <remarks>
		/// 
		/// </remarks>
		public override byte[] GetBytes(int cb) {
			throw new NotImplementedException();
		}

		/// <summary>
		/// Resets the state of the operation.
		/// </summary>
		/// <remarks>
		/// This method is automatically called if the <see cref="Salt"/>, <see cref="BlockSize"/>,
		/// <see cref="Cost"/> or <see cref="Parallelization"/> parameter is modified.
		/// </remarks>
		public override void Reset() {
			throw new NotImplementedException();
		}

		byte[] Salsa(byte[] input) {
			throw new NotImplementedException();
		}

		byte[] ScryptBlockMix(byte[] input) {
			throw new NotImplementedException();
		}

		byte[] ScryptROMix(byte[] input) {
			throw new NotImplementedException();
		}
	}
}
