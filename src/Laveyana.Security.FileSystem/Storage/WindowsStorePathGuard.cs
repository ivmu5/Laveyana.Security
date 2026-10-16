using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Laveyana.Security.FileSystem.Storage;

/// <summary>Strict Windows ACL/owner preflight; this is not handle-relative anti-race I/O.</summary>
[SupportedOSPlatform("windows")]
internal static class WindowsStorePathGuard
{
    private const FileSystemRights DangerousAncestorRights = FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership | FileSystemRights.WriteAttributes |
        FileSystemRights.WriteExtendedAttributes;

    internal static void CreateRoot(string root)
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ??
            throw new UnauthorizedAccessException("The current Windows identity is unavailable.");
        DirectorySecurity descriptor = new();
        descriptor.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        descriptor.SetOwner(user);
        descriptor.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        foreach (WellKnownSidType sidType in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            descriptor.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sidType, null),
                FileSystemRights.FullControl, InheritanceFlags.ContainerInherit |
                InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }

        FileSystemAclExtensions.CreateDirectory(descriptor, root);
        ValidateRoot(root);
    }

    internal static void ValidateRoot(string root)
    {
        if (root.StartsWith(@"\\", StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("UNC/network-backed store roots are not supported.");
        }

        DirectoryInfo? directory = new(root);
        bool isRoot = true;
        while (directory is not null)
        {
            ValidateEntry(directory.FullName, true);
            ValidateAcl(FileSystemAclExtensions.GetAccessControl(directory), isRoot);
            isRoot = false;
            directory = directory.Parent;
        }
    }

    internal static void ValidateFile(string path)
    {
        ValidateEntry(path, false);
        ValidateAcl(FileSystemAclExtensions.GetAccessControl(new FileInfo(path)), true);
    }

    private static void ValidateEntry(string path, bool directory)
    {
        FileAttributes attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0 ||
            ((attributes & FileAttributes.Directory) != 0) != directory)
        {
            throw new IOException("Redirected or incorrectly typed store path is not trusted.");
        }
    }

    private static void ValidateAcl(FileSystemSecurity descriptor, bool isolated)
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ??
            throw new UnauthorizedAccessException("Windows user SID is unavailable.");
        SecurityIdentifier system = new(WellKnownSidType.LocalSystemSid, null);
        SecurityIdentifier admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        RawSecurityDescriptor raw = new(descriptor.GetSecurityDescriptorBinaryForm(), 0);
        if ((raw.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0 ||
            raw.DiscretionaryAcl is null)
        {
            throw new UnauthorizedAccessException("Store ACL is missing or null.");
        }

        if (isolated)
        {
            IdentityReference? owner = descriptor.GetOwner(typeof(SecurityIdentifier));
            // Elevated Windows processes can create files whose default owner is
            // BUILTIN\Administrators instead of the user's own SID. Trust this
            // owner only when it is also the current token's default owner;
            // Administrators already has explicit FullControl in the store ACL.
            bool isCurrentUserOwner = user.Equals(owner);
            bool isCurrentAdminTokenOwner = admins.Equals(identity.Owner) && admins.Equals(owner);
            if (!isCurrentUserOwner && !isCurrentAdminTokenOwner)
            {
                throw new UnauthorizedAccessException("Store entry has an unexpected owner.");
            }
        }

        foreach (AuthorizationRule rule in descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule is not FileSystemAccessRule access || access.AccessControlType != AccessControlType.Allow)
            {
                continue;
            }

            SecurityIdentifier sid = (SecurityIdentifier)access.IdentityReference;
            if (sid.Equals(user) || sid.Equals(system) || sid.Equals(admins))
            {
                continue;
            }

            // Inherit-only ACEs have no effect on the ancestor itself. The
            // protected store root is validated separately with all its ACEs.
            if (!isolated && (access.PropagationFlags & PropagationFlags.InheritOnly) != 0)
            {
                continue;
            }

            if (isolated || (access.FileSystemRights & DangerousAncestorRights) != 0)
            {
                throw new UnauthorizedAccessException("Store ACL grants unsafe access to another principal.");
            }
        }
    }
}
