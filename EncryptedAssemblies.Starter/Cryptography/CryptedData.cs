using System;
using System.IO;

namespace EncryptedAssemblies.Starter.Cryptography
{
public sealed class CryptedData
{
    /// <summary>
    /// Возвращает или устанавливает вектор инициализации.
    /// </summary>
    public byte[] IV
    {
        get;
        set;
    }

    /// <summary>
    /// Возвращает или устанавливает данные.
    /// </summary>
    public byte[] EncryptedSource
    {
        get;
        set;
    }

    /// <summary>
    /// Возвращает вектор инициализации и зашифрованные данные в виде единого массива.
    /// </summary>
    public byte[] ToArray()
    {
        using (MemoryStream ms = new MemoryStream())
        {
            Store(ms);
            return ms.ToArray();
        }
    }

    /// <summary>
    /// Сохраняет вектор инициализации и зашифрованные данные в поток.
    /// </summary>
    /// <param name="output">Поток, в который необходимо сохранить данные.</param>
    public void Store(Stream output)
    {
        Validate(this);
        if (!output.CanWrite)
        {
            throw new ArgumentException("В переданный поток запрещена запись", "output");
        }
                
        using (BinaryWriter bw = new BinaryWriter(output))
        {
            bw.Write(IV.Length);
            bw.Write(IV);
            bw.Write(EncryptedSource.Length);
            bw.Write(EncryptedSource);
        }
    }

    /// <summary>
    /// Возвращает зашифрованные данные и вектор инициализации.
    /// </summary>
    /// <param name="input">Поток с входящими данными.</param>
    public static CryptedData Create(Stream input)
    {
        if (!input.CanRead)
        {
            throw new ArgumentException("Из входящего потока запрещено чтение", "input");
        }
        CryptedData data = new CryptedData();
        using (BinaryReader reader = new BinaryReader(input))
        {
            int ivLength = reader.ReadInt32();
            data.IV = reader.ReadBytes(ivLength);
            int sourceLength = reader.ReadInt32();
            data.EncryptedSource = reader.ReadBytes(sourceLength);
        }
        Validate(data);
        return data;
    }

    /// <summary>
    /// Проверяет валидность данных.
    /// </summary>
    /// <param name="data">Данные, которые необходимо проверить.</param>
    private static void Validate(CryptedData data)
    {
        if (data.IV == null || data.IV.Length == 0)
        {
            throw new ArgumentException("IV должно быть ненулевой длинны");
        }
        if (data.IV.Length > byte.MaxValue)
        {
            throw new ArgumentException("Длинна IV не может быть больше " + byte.MaxValue);
        }
        if (data.EncryptedSource == null || data.EncryptedSource.Length == 0)
        {
            throw new ArgumentException("Souce должно быть ненулевой длинны");
        }
    }
}
}
