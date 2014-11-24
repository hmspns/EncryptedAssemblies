using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;

namespace EncryptedAssemblies.Starter.Cryptography
{
    [CLSCompliant(false)]
    public sealed class InsecureString : IDisposable, IEnumerable<char>
    {
        internal InsecureString(SecureString secureString)
        {
            _secureString = secureString;
            Initialize();
        }

        public string Value { get; private set; }

        private readonly SecureString _secureString;
        private GCHandle _gcHandle;

#if !DEBUG
        [DebuggerHidden]
#endif
        private void Initialize()
        {
            unsafe
            {
                // We are about to create an unencrypted version of our sensitive string and store it in memory.
                // Don't let anyone (GC) make a copy.
                // To do this, create a new gc handle so we can "pin" the memory.
                // The gc handle will be pinned and later, we will put info in this string.
                _gcHandle = new GCHandle();
                // insecurePointer will be temporarily used to access the SecureString
                IntPtr insecurePointer = IntPtr.Zero;
                RuntimeHelpers.TryCode code = delegate
                {
                    // create a new string of appropriate length that is filled with 0's
                    Value = new string((char)0, _secureString.Length);
                    // Even though we are in the ExecuteCodeWithGuaranteedCleanup, processing can be interupted.
                    // We need to make sure nothing happens between when memory is allocated and
                    // when _gcHandle has been assigned the value. Otherwise, we can't cleanup later.
                    // PrepareConstrainedRegions is better than a try/catch. Not even a threadexception will interupt this processing.
                    // A CER is not the same as ExecuteCodeWithGuaranteedCleanup. A CER does not have a cleanup.

                    Action alloc = delegate { _gcHandle = GCHandle.Alloc(Value, GCHandleType.Pinned); };
                    ExecuteInConstrainedRegion(alloc);

                    // Even though we are in the ExecuteCodeWithGuaranteedCleanup, processing can be interupted.
                    // We need to make sure nothing happens between when memory is allocated and
                    // when insecurePointer has been assigned the value. Otherwise, we can't cleanup later.
                    // PrepareConstrainedRegions is better than a try/catch. Not even a threadexception will interupt this processing.
                    // A CER is not the same as ExecuteCodeWithGuaranteedCleanup. A CER does not have a cleanup.
                    Action toBSTR = delegate { insecurePointer = Marshal.SecureStringToBSTR(_secureString); };
                    ExecuteInConstrainedRegion(toBSTR);

                    // get a pointer to our new "pinned" string
                    char* value = (char*)_gcHandle.AddrOfPinnedObject();
                    // get a pointer to the unencrypted string
                    char* charPointer = (char*)insecurePointer;
                    // copy
                    for (int i = 0; i < _secureString.Length; i++)
                    {
                        value[i] = charPointer[i];
                    }
                };
                RuntimeHelpers.CleanupCode cleanup = delegate
                {
                    // insecurePointer was temporarily used to access the securestring
                    // set the string to all 0's and then clean it up. this is important.
                    // this prevents sniffers from seeing the sensitive info as it is cleaned up.
                    if (insecurePointer != IntPtr.Zero)
                    {
                        Marshal.ZeroFreeBSTR(insecurePointer);
                    }
                };
                // Better than a try/catch. Not even a threadexception will bypass the cleanup code
                RuntimeHelpers.ExecuteCodeWithGuaranteedCleanup(code, cleanup, null);
            }
        }

#if !DEBUG
        [DebuggerHidden]
#endif
        public void Dispose()
        {
            unsafe
            {
                // we have created an insecurestring
                if (_gcHandle.IsAllocated)
                {
                    // get the address of our gchandle and set all chars to 0's
                    char* insecurePointer = (char*)_gcHandle.AddrOfPinnedObject();
                    for (int i = 0; i < _secureString.Length; i++)
                    {
                        insecurePointer[i] = (char)0;
                    }
#if DEBUG
                    string disposed = "¡DISPOSED¡";
                    disposed = disposed.Substring(0, Math.Min(disposed.Length, _secureString.Length));
                    for (int i = 0; i < disposed.Length; ++i)
                    {
                        insecurePointer[i] = disposed[i];
                    }
#endif
                    _gcHandle.Free();
                }
            }
        }

        public IEnumerator<char> GetEnumerator()
        {
            if (_gcHandle.IsAllocated)
            {
                return Value.GetEnumerator();
            }
            else
            {
                return new List<char>().GetEnumerator();
            }
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        private static void ExecuteInConstrainedRegion(Action action)
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
            }
            finally
            {
                action();
            }
        }
    }
}
