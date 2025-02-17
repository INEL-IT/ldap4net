﻿// ReSharper disable InconsistentNaming

namespace LdapForNet.Native
{
    public static partial class Native
    {
        public enum ResultCode
        {
            LDAP_NOT_SUPPORTED = -12,
            LDAP_PARAM_ERROR = -9,
            Success = 0,
            OperationsError = 1,
            ProtocolError = 2,
            TimeLimitExceeded = 3,
            SizeLimitExceeded = 4,
            CompareFalse = 5,
            CompareTrue = 6,
            AuthMethodNotSupported = 7,
            StrongAuthRequired = 8,
            ReferralV2 = 9,
            Referral = 10,
            AdminLimitExceeded = 11,
            UnavailableCriticalExtension = 12,
            ConfidentialityRequired = 13,
            SaslBindInProgress = 14,
            NoSuchAttribute = 16,
            UndefinedAttributeType = 17,
            InappropriateMatching = 18,
            ConstraintViolation = 19,
            AttributeOrValueExists = 20,
            InvalidAttributeSyntax = 21,
            NoSuchObject = 32,
            AliasProblem = 33,
            InvalidDNSyntax = 34,
            AliasDereferencingProblem = 36,
            InappropriateAuthentication = 48,
            InvalidCredentials = 49,
            InsufficientAccessRights = 50,
            Busy = 51,
            Unavailable = 52,
            UnwillingToPerform = 53,
            LoopDetect = 54,
            SortControlMissing = 60,
            OffsetRangeError = 61,
            NamingViolation = 64,
            ObjectClassViolation = 65,
            NotAllowedOnNonLeaf = 66,
            NotAllowedOnRdn = 67,
            EntryAlreadyExists = 68,
            ObjectClassModificationsProhibited = 69,
            ResultsTooLarge = 70,
            AffectsMultipleDsas = 71,
            VirtualListViewError = 76,
            Other = 80,
            ServerDown = 81,
            LocalError = 82,
            EncodingError = 83,
            DecodingError = 84,
            Timeout = 85,
            AuthUnknown = 86,
            FilterError = 87,
            UserCanceled = 88,
            ParamError = 89,
            NoMemory = 90,
            ConnectError = 91,
            NotSupported = 92,
            ControlNotFound = 93,
            NoResultsReturned = 94,
            MoreResultsToReturn = 95,
            ClientLoop = 96,
            ReferralLimitExceeded = 97,
            InvalidResponse = 100,
            AmbiguousResponse = 101,
            TlsNotSupported = 112,
            IntermediateResponse = 113,
            UnknownType = 114,
            Canceled = 118,
            NoSuchOperation = 119,
            TooLate = 120,
            CannotCancel = 121,
            AssertionFailed = 122,
            AuthorizationDenied = 123,
            NoOperation = 16654
        }
    }
}