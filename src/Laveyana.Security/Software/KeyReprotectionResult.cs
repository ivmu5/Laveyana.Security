using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Protection;

namespace Laveyana.Security.Software;

/// <summary>One confirmed re-protection outcome with the durable aggregate revision.</summary>
public readonly record struct KeyReprotectionResult(KeyReprotectionStatus Status, KeyStoreRevision Revision);
