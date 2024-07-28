// GOOD ENOUGH
#include "TokenInfo.h"
#include "Helper.h"

#include <sddl.h>
#include <iostream>
#include <iomanip>
#pragma comment(lib, "Advapi32.lib")

void* GetTokenInfo(HANDLE token, TOKEN_INFORMATION_CLASS desiredInfo) {
	DWORD length = 0;
	GetTokenInformation(token, desiredInfo, nullptr, 0, &length);
	if (length == 0) {
		ThrowSysError();
	}

	void* output = malloc(length);
	if (!GetTokenInformation(token, desiredInfo, output, length, &length)) {
		ThrowSysError();
	}

	return output;
}

void FormatHex(BYTE* value, DWORD length) {
	std::wcout << L"0x" << std::hex << std::uppercase << std::setw(2) << std::setfill(L'0');
	for (DWORD i = length - 1; i != 0xFFFFFFFF; i--)
	{
		std::wcout << value[i];
	}
	std::wcout << std::dec;
}
void FormatBinary(BYTE* value, DWORD length) {
	for (DWORD i = 0; i < length; i++)
	{
		if (i != 0) { std::wcout << L" "; }
		if ((value[i] & 128) == 0) { std::wcout << L"0"; }
		else { std::wcout << L"1"; }
		if ((value[i] & 64) == 0) { std::wcout << L"0"; }
		else { std::wcout << L"1"; }
		if ((value[i] & 32) == 0) { std::wcout << L"0"; }
		else { std::wcout << L"1"; }
		if ((value[i] & 16) == 0) { std::wcout << L"0"; }
		else { std::wcout << L"1"; }
		if ((value[i] & 8) == 0) { std::wcout << L"0"; }
		else { std::wcout << L"1"; }
		if ((value[i] & 4) == 0) { std::wcout << L"0"; }
		else { std::wcout << L"1"; }
		if ((value[i] & 2) == 0) { std::wcout << L"0"; }
		else { std::wcout << L"1"; }
		if ((value[i] & 1) == 0) { std::wcout << L"0"; }
		else { std::wcout << L"1"; }
	}
}
void FormatBool(DWORD value) {
	if (value == 0) {
		std::wcout << L"False";
	}
	else {
		std::wcout << L"True";
	}
}
void FormatSID(PSID value) {
	TCHAR name[256];
	TCHAR domain[256];
	DWORD nameLen = sizeof(name) / sizeof(TCHAR);
	DWORD domainLen = sizeof(domain) / sizeof(TCHAR);
	SID_NAME_USE sidType;
	BOOL valid = LookupAccountSid(NULL, value, name, &nameLen, domain, &domainLen, &sidType);

	if (valid) {
		if (domainLen != 0)
		{
			std::wcout << domain << L"/";
		}
		std::wcout << name;
	}
	else {
		sidType = SidTypeInvalid;
	}

	switch (sidType) {
	case SidTypeUser:
		std::wcout << L" (User)";
		break;
	case SidTypeGroup:
		std::wcout << L" (Group)";
		break;
	case SidTypeDomain:
		std::wcout << L" (Domain)";
		break;
	case SidTypeAlias:
		std::wcout << L" (Alias)";
		break;
	case SidTypeWellKnownGroup:
		std::wcout << L" (Well Known Group)";
		break;
	case SidTypeDeletedAccount:
		std::wcout << L" (Deleted Account)";
		break;
	case SidTypeComputer:
		std::wcout << L" (Computer)";
		break;
	case SidTypeLabel:
		std::wcout << L" (Label)";
		break;
	case SidTypeLogonSession:
		std::wcout << L" (Logon Session)";
		break;
	case SidTypeInvalid:
	case SidTypeUnknown:
	default:
		if (value == 0) { std::wcout << L"Null SID"; }
		else { std::wcout << L"Invalid/Unknown SID"; }
		break;
	}
}
void FormatLUID(LUID value) {
	WCHAR privilegeName[256];
	DWORD nameLen = sizeof(privilegeName) / sizeof(privilegeName[0]);

	if (LookupPrivilegeName(NULL, &value, privilegeName, &nameLen)) {
		std::wcout << privilegeName;
	}
	else {
		FormatHex(reinterpret_cast<BYTE*>(&value), 8);
	}
}

void PrintTokenHandle(HANDLE token) {
	std::wcout << L"Token Handle: "; FormatHex(reinterpret_cast<BYTE*>(&token), 8); std::wcout << std::endl;
}

void PrintTokenUser(HANDLE token) {
	try {
		TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(GetTokenInfo(token, TokenUser));

		std::wcout << L"Token User:" << std::endl;
		std::wcout << L"    SID: "; FormatSID(tokenUser->User.Sid); std::wcout << std::endl;
		std::wcout << L"    Attributes: "; FormatBinary(reinterpret_cast<BYTE*>(&tokenUser->User.Attributes), 4); std::wcout << std::endl;

		free(tokenUser);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenGroups(HANDLE token) {
	try {
		TOKEN_GROUPS* tokenGroups = reinterpret_cast<TOKEN_GROUPS*>(GetTokenInfo(token, TokenGroups));

		std::wcout << L"Token Groups [" << tokenGroups->GroupCount << L"]:"; if (tokenGroups->GroupCount == 0) { std::wcout << L" None"; } std::wcout << std::endl;
		for (DWORD i = 0; i < tokenGroups->GroupCount; i++)
		{
			if (i != 0) { std::wcout << std::endl; }
			std::wcout << L"   SID: "; FormatSID(tokenGroups->Groups[i].Sid); std::wcout << std::endl;
			std::wcout << L"   Attributes: "; FormatBinary(reinterpret_cast<BYTE*>(&tokenGroups->Groups[i].Attributes), 4); std::wcout << std::endl;
		}

		free(tokenGroups);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenPrivileges(HANDLE token) {
	try {
		TOKEN_PRIVILEGES* tokenPrivileges = reinterpret_cast<TOKEN_PRIVILEGES*>(GetTokenInfo(token, TokenPrivileges));

		std::wcout << L"Token Privileges [" << tokenPrivileges->PrivilegeCount << L"]:"; if (tokenPrivileges->PrivilegeCount == 0) { std::wcout << L" None"; } std::wcout << std::endl;
		for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++)
		{
			if (i != 0) { std::wcout << std::endl; }
			std::wcout << "    LUID: "; FormatLUID(tokenPrivileges->Privileges[i].Luid); std::wcout << std::endl;
			std::wcout << "    Attributes: "; FormatBinary(reinterpret_cast<BYTE*>(&tokenPrivileges->Privileges[i].Attributes), 4); std::wcout << std::endl;
		}

		free(tokenPrivileges);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenOwner(HANDLE token) {
	try {
		TOKEN_OWNER* tokenOwner = reinterpret_cast<TOKEN_OWNER*>(GetTokenInfo(token, TokenOwner));

		std::wcout << L"Token Owner: "; FormatSID(tokenOwner->Owner); std::wcout << std::endl;

		free(tokenOwner);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenPrimaryGroup(HANDLE token) {
	try {
		TOKEN_PRIMARY_GROUP* tokenPrimaryGroup = reinterpret_cast<TOKEN_PRIMARY_GROUP*>(GetTokenInfo(token, TokenPrimaryGroup));

		std::wcout << L"Token Primary Group: "; FormatSID(tokenPrimaryGroup->PrimaryGroup); std::wcout << std::endl;

		free(tokenPrimaryGroup);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenDefaultDacl(HANDLE token) {
	try {
		TOKEN_DEFAULT_DACL* tokenDefaultDacl = reinterpret_cast<TOKEN_DEFAULT_DACL*>(GetTokenInfo(token, TokenDefaultDacl));

		std::wcout << L"Token Default DACL:" << std::endl;
		std::wcout << L"    ACL Revision: " << tokenDefaultDacl->DefaultDacl->AclRevision << std::endl;
		std::wcout << L"    ACL Size: " << tokenDefaultDacl->DefaultDacl->AclSize << std::endl;
		std::wcout << L"    ACE List [" << tokenDefaultDacl->DefaultDacl->AceCount << L"]:"; if (tokenDefaultDacl->DefaultDacl->AceCount == 0) { std::wcout << L" None"; } std::wcout << std::endl;
		for (DWORD i = 0; i < tokenDefaultDacl->DefaultDacl->AceCount; i++)
		{
			if (i != 0) { std::wcout << std::endl; }
			ACE_HEADER* currentACE = nullptr;
			GetAce(tokenDefaultDacl->DefaultDacl, i, reinterpret_cast<void**>(&currentACE));
			std::wcout << L"    Type: " << currentACE->AceType << std::endl;
			std::wcout << L"    Flags: " << currentACE->AceFlags << std::endl;
			std::wcout << L"    Size: " << currentACE->AceSize << std::endl;
		}

		free(tokenDefaultDacl);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenSource(HANDLE token) {
	try {
		TOKEN_SOURCE* tokenSource = reinterpret_cast<TOKEN_SOURCE*>(GetTokenInfo(token, TokenSource));

		std::wcout << L"Token Source: " << tokenSource->SourceName << std::endl;

		free(tokenSource);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenType(HANDLE token) {
	try {
		TOKEN_TYPE* tokenType = reinterpret_cast<TOKEN_TYPE*>(GetTokenInfo(token, TokenType));

		std::wcout << L"Token Type: ";
		if (*tokenType == TokenPrimary) {
			std::wcout << L"Primary";
		}
		else if (*tokenType == TokenImpersonation) {
			std::wcout << L"Impersonation";
		}
		else {
			std::wcout << L"Invalid";
		}
		std::wcout << std::endl;

		free(tokenType);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenImpersonationLevel(HANDLE token) {
	try {
		TOKEN_TYPE* tokenType = reinterpret_cast<TOKEN_TYPE*>(GetTokenInfo(token, TokenType));
		if (*tokenType != TokenImpersonation) {
			std::wcout << L"Token Impersonation Level: N/A" << std::endl;
			free(tokenType);
			return;
		}
		free(tokenType);

		SECURITY_IMPERSONATION_LEVEL* tokenImpersonationLevel = reinterpret_cast<SECURITY_IMPERSONATION_LEVEL*>(GetTokenInfo(token, TokenImpersonationLevel));

		std::wcout << L"Token Impersonation Level: ";
		if (*tokenImpersonationLevel == SecurityAnonymous) {
			std::wcout << L"Anonymous";
		}
		else if (*tokenImpersonationLevel == SecurityIdentification) {
			std::wcout << L"Identification";
		}
		else if (*tokenImpersonationLevel == SecurityImpersonation) {
			std::wcout << L"Impersonation";
		}
		else if (*tokenImpersonationLevel == SecurityDelegation) {
			std::wcout << L"Delegation";
		}
		else {
			std::wcout << L"Invalid";
		}
		std::wcout << std::endl;

		free(tokenImpersonationLevel);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenStatistics(HANDLE token) {
	try {
		TOKEN_STATISTICS* tokenStatistics = reinterpret_cast<TOKEN_STATISTICS*>(GetTokenInfo(token, TokenStatistics));

		std::wcout << L"Token Statistics:" << std::endl;
		std::wcout << L"    Token ID: "; FormatLUID(tokenStatistics->TokenId); std::wcout << std::endl;
		std::wcout << L"    Authentication ID: "; FormatLUID(tokenStatistics->AuthenticationId); std::wcout << std::endl;
		std::wcout << L"    Token Type: ";
		if (tokenStatistics->TokenType == TokenPrimary) {
			std::wcout << L"Primary";
		}
		else if (tokenStatistics->TokenType == TokenImpersonation) {
			std::wcout << L"Impersonation";
		}
		else {
			std::wcout << L"Invalid";
		}
		std::wcout << std::endl;
		if (tokenStatistics->TokenType != TokenImpersonation) {
			std::wcout << L"    Impersonation Level: N/A" << std::endl;
		}
		else {
			std::wcout << L"    Impersonation Level: ";
			if (tokenStatistics->ImpersonationLevel == SecurityAnonymous) {
				std::wcout << L"Anonymous";
			}
			else if (tokenStatistics->ImpersonationLevel == SecurityIdentification) {
				std::wcout << L"Identification";
			}
			else if (tokenStatistics->ImpersonationLevel == SecurityImpersonation) {
				std::wcout << L"Impersonation";
			}
			else if (tokenStatistics->ImpersonationLevel == SecurityDelegation) {
				std::wcout << L"Delegation";
			}
			else {
				std::wcout << L"Invalid";
			}
			std::wcout << std::endl;
		}
		std::wcout << L"    Dynamic Charged: " << tokenStatistics->DynamicCharged << std::endl;
		std::wcout << L"    Dynamic Available: " << tokenStatistics->DynamicAvailable << std::endl;
		std::wcout << L"    Group Count: " << tokenStatistics->GroupCount << std::endl;
		std::wcout << L"    Privilege Count: " << tokenStatistics->PrivilegeCount << std::endl;
		std::wcout << L"    Modified ID: "; FormatLUID(tokenStatistics->ModifiedId); std::wcout << std::endl;

		free(tokenStatistics);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenRestrictedSids(HANDLE token) {
	try {
		TOKEN_GROUPS* tokenRestrictedSids = reinterpret_cast<TOKEN_GROUPS*>(GetTokenInfo(token, TokenRestrictedSids));

		std::wcout << L"Token Restricted SIDs [" << tokenRestrictedSids->GroupCount << L"]:"; if (tokenRestrictedSids->GroupCount == 0) { std::wcout << L" None"; } std::wcout << std::endl;
		for (DWORD i = 0; i < tokenRestrictedSids->GroupCount; i++)
		{
			if (i != 0) { std::wcout << std::endl; }
			std::wcout << L"    SID: "; FormatSID(tokenRestrictedSids->Groups[i].Sid); std::wcout << std::endl;
			std::wcout << L"    Attributes: "; FormatBinary(reinterpret_cast<BYTE*>(&tokenRestrictedSids->Groups[i].Attributes), 4); std::wcout << std::endl;
		}

		free(tokenRestrictedSids);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenSessionID(HANDLE token) {
	try {
		DWORD* tokenSessionId = reinterpret_cast<DWORD*>(GetTokenInfo(token, TokenSessionId));

		std::wcout << L"Token Session ID: " << *tokenSessionId << std::endl;

		free(tokenSessionId);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenGroupsAndPrivileges(HANDLE token) {
	try {
		TOKEN_GROUPS_AND_PRIVILEGES* tokenGroupsAndPrivileges = reinterpret_cast<TOKEN_GROUPS_AND_PRIVILEGES*>(GetTokenInfo(token, TokenGroupsAndPrivileges));

		std::wcout << L"Token Groups And Privileges: TODO" << std::endl;

		free(tokenGroupsAndPrivileges);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenSessionReference(HANDLE token) {
	try {
		void* tokenSessionReference = reinterpret_cast<void*>(GetTokenInfo(token, TokenSessionReference));

		std::wcout << L"Token Session Refrence: TODO" << std::endl;

		free(tokenSessionReference);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenSandBoxInert(HANDLE token) {
	try {
		DWORD* tokenSandBoxInert = reinterpret_cast<DWORD*>(GetTokenInfo(token, TokenSandBoxInert));

		std::wcout << L"Token Sand Box Inert: "; FormatBool(*tokenSandBoxInert); std::wcout << std::endl;

		free(tokenSandBoxInert);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenAuditPolicy(HANDLE token) {
	try {
		void* tokenAuditPolicy = reinterpret_cast<void*>(GetTokenInfo(token, TokenAuditPolicy));

		std::wcout << L"Token Audit Policy: TODO" << std::endl;

		free(tokenAuditPolicy);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenOrigin(HANDLE token) {
	try {
		TOKEN_ORIGIN* tokenOrigin = reinterpret_cast<TOKEN_ORIGIN*>(GetTokenInfo(token, TokenOrigin));

		std::wcout << L"Token Origin: "; FormatLUID(tokenOrigin->OriginatingLogonSession); std::wcout << std::endl;

		free(tokenOrigin);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenElevationType(HANDLE token) {
	try {
		TOKEN_ELEVATION_TYPE* tokenElevationType = reinterpret_cast<TOKEN_ELEVATION_TYPE*>(GetTokenInfo(token, TokenElevationType));

		std::wcout << L"Token Elevation Type: ";
		if (*tokenElevationType == TokenElevationTypeDefault) {
			std::wcout << L"Default";
		}
		else if (*tokenElevationType == TokenElevationTypeFull) {
			std::wcout << L"Full";
		}
		else if (*tokenElevationType == TokenElevationTypeLimited) {
			std::wcout << L"Limited";
		}
		else {
			std::wcout << L"Invalid";
		}
		std::wcout << std::endl;

		free(tokenElevationType);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenLinkedToken(HANDLE token) {
	try {
		TOKEN_LINKED_TOKEN* tokenLinkedToken = reinterpret_cast<TOKEN_LINKED_TOKEN*>(GetTokenInfo(token, TokenLinkedToken));

		std::wcout << L"Token Linked Token: "; FormatHex(reinterpret_cast<BYTE*>(&tokenLinkedToken->LinkedToken), 8); std::wcout << std::endl;

		free(tokenLinkedToken);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenElevation(HANDLE token) {
	try {
		TOKEN_ELEVATION* tokenElevation = reinterpret_cast<TOKEN_ELEVATION*>(GetTokenInfo(token, TokenElevation));

		std::wcout << L"Token Is Elevated: "; FormatBool(tokenElevation->TokenIsElevated); std::wcout << std::endl;

		free(tokenElevation);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenHasRestrictions(HANDLE token) {
	try {
		DWORD* tokenHasRestrictions = reinterpret_cast<DWORD*>(GetTokenInfo(token, TokenHasRestrictions));

		std::wcout << L"Token Has Restrictions: "; FormatBool(*tokenHasRestrictions); std::wcout << std::endl;

		free(tokenHasRestrictions);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenAccessInformation(HANDLE token) {
	try {
		TOKEN_ACCESS_INFORMATION* tokenAccessInformation = reinterpret_cast<TOKEN_ACCESS_INFORMATION*>(GetTokenInfo(token, TokenAccessInformation));

		std::wcout << L"Token Access Information: TODO" << std::endl;

		free(tokenAccessInformation);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenVirtualizationAllowed(HANDLE token) {
	try {
		DWORD* tokenVirtualizationAllowed = reinterpret_cast<DWORD*>(GetTokenInfo(token, TokenVirtualizationAllowed));

		std::wcout << L"Token Virtualization Allowed: "; FormatBool(*tokenVirtualizationAllowed); std::wcout << std::endl;

		free(tokenVirtualizationAllowed);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenVirtualizationEnabled(HANDLE token) {
	try {
		DWORD* tokenVirtualizationEnabled = reinterpret_cast<DWORD*>(GetTokenInfo(token, TokenVirtualizationEnabled));

		std::wcout << L"Token Virtualization Enabled: "; FormatBool(*tokenVirtualizationEnabled); std::wcout << std::endl;

		free(tokenVirtualizationEnabled);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenIntegrityLevel(HANDLE token) {
	try {
		TOKEN_MANDATORY_LABEL* tokenIntegrityLevel = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(GetTokenInfo(token, TokenIntegrityLevel));

		std::wcout << L"Token Integrity Level:" << std::endl;
		std::wcout << "    SID: "; FormatSID(tokenIntegrityLevel->Label.Sid); std::wcout << std::endl;
		std::wcout << "    Attributes: "; FormatBinary(reinterpret_cast<BYTE*>(&tokenIntegrityLevel->Label.Attributes), 4); std::wcout << std::endl;

		free(tokenIntegrityLevel);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenUIAccess(HANDLE token) {
	try {
		DWORD* tokenUIAccess = reinterpret_cast<DWORD*>(GetTokenInfo(token, TokenUIAccess));

		std::wcout << L"Token UI Access: "; FormatBool(*tokenUIAccess); std::wcout << std::endl;

		free(tokenUIAccess);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenMandatoryPolicy(HANDLE token) {
	try {
		TOKEN_MANDATORY_POLICY* tokenMandatoryPolicy = reinterpret_cast<TOKEN_MANDATORY_POLICY*>(GetTokenInfo(token, TokenMandatoryPolicy));

		std::wcout << L"Token Mandatory Policy: " << tokenMandatoryPolicy->Policy << std::endl;

		free(tokenMandatoryPolicy);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenLogonSid(HANDLE token) {
	try {
		TOKEN_GROUPS* tokenLogonSid = reinterpret_cast<TOKEN_GROUPS*>(GetTokenInfo(token, TokenLogonSid));

		std::wcout << L"Token Logon Sids [" << tokenLogonSid->GroupCount << L"]:"; if (tokenLogonSid->GroupCount == 0) { std::wcout << L" None"; } std::wcout << std::endl;
		for (DWORD i = 0; i < tokenLogonSid->GroupCount; i++)
		{
			if (i != 0) { std::wcout << std::endl; }
			std::wcout << "    SID: "; FormatSID(tokenLogonSid->Groups[i].Sid); std::wcout << std::endl;
			std::wcout << "    Attributes: "; FormatBinary(reinterpret_cast<BYTE*>(&tokenLogonSid->Groups[i].Attributes), 4); std::wcout << std::endl;
		}

		free(tokenLogonSid);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenIsAppContainer(HANDLE token) {
	try {
		DWORD* tokenIsAppContainer = reinterpret_cast<DWORD*>(GetTokenInfo(token, TokenIsAppContainer));

		std::wcout << L"Token Is App Container: "; FormatBool(*tokenIsAppContainer); std::wcout << std::endl;

		free(tokenIsAppContainer);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenCapabilities(HANDLE token) {
	try {
		TOKEN_GROUPS* tokenCapabilities = reinterpret_cast<TOKEN_GROUPS*>(GetTokenInfo(token, TokenCapabilities));

		std::wcout << L"Token Capabilities [" << tokenCapabilities->GroupCount << L"]:"; if (tokenCapabilities->GroupCount == 0) { std::wcout << L" None"; } std::wcout << std::endl;
		for (DWORD i = 0; i < tokenCapabilities->GroupCount; i++)
		{
			if (i != 0) { std::wcout << std::endl; }
			std::wcout << "    SID: "; FormatSID(tokenCapabilities->Groups[i].Sid); std::wcout << std::endl;
			std::wcout << "    Attributes: "; FormatBinary(reinterpret_cast<BYTE*>(&tokenCapabilities->Groups[i].Attributes), 4); std::wcout << std::endl;
		}

		free(tokenCapabilities);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenAppContainerSid(HANDLE token) {
	try {
		TOKEN_APPCONTAINER_INFORMATION* tokenAppContainerSid = reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(GetTokenInfo(token, TokenAppContainerSid));

		std::wcout << L"Token App Container SID: "; FormatSID(tokenAppContainerSid->TokenAppContainer); std::wcout << std::endl;

		free(tokenAppContainerSid);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenAppContainerNumber(HANDLE token) {
	try {
		DWORD* tokenAppContainerNumber = reinterpret_cast<DWORD*>(GetTokenInfo(token, TokenAppContainerNumber));

		std::wcout << L"Token App Container Number: " << *tokenAppContainerNumber << std::endl;

		free(tokenAppContainerNumber);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenUserClaimAttributes(HANDLE token) {
	try {
		CLAIM_SECURITY_ATTRIBUTES_INFORMATION* tokenUserClaimAttributes = reinterpret_cast<CLAIM_SECURITY_ATTRIBUTES_INFORMATION*>(GetTokenInfo(token, TokenUserClaimAttributes));

		std::wcout << L"Token User Claim Attributes:" << std::endl;
		std::wcout << L"    Version: " << tokenUserClaimAttributes->Version << std::endl;
		std::wcout << L"    Reserved: " << tokenUserClaimAttributes->Reserved << std::endl;
		std::wcout << L"    Attributes [" << tokenUserClaimAttributes->AttributeCount << "]:"; if (tokenUserClaimAttributes->AttributeCount == 0) { std::wcout << " None"; } std::wcout << std::endl;
		for (DWORD i = 0; i < tokenUserClaimAttributes->AttributeCount; i++)
		{
			CLAIM_SECURITY_ATTRIBUTE_V1 attribute = tokenUserClaimAttributes->Attribute.pAttributeV1[i];
			std::wcout << L"        Name: " << attribute.Name << std::endl;
			std::wcout << L"        Value Type: " << attribute.ValueType << std::endl;
			std::wcout << L"        Reserved: " << attribute.Reserved << std::endl;
			std::wcout << L"        Flags: "; FormatBinary(reinterpret_cast<BYTE*>(&attribute.Flags), 4); std::wcout << std::endl;
			std::wcout << L"        Value Count: " << attribute.ValueCount << std::endl;
			std::wcout << L"        Values:" << std::endl;
			for (DWORD j = 0; j < attribute.ValueCount; j++)
			{
				std::wcout << L"            TODO" << std::endl;
			}
			std::wcout << std::endl;
		}

		free(tokenUserClaimAttributes);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenDeviceClaimAttributes(HANDLE token) {
	try {
		CLAIM_SECURITY_ATTRIBUTES_INFORMATION* tokenDeviceClaimAttributes = reinterpret_cast<CLAIM_SECURITY_ATTRIBUTES_INFORMATION*>(GetTokenInfo(token, TokenDeviceClaimAttributes));

		std::wcout << L"Token Device Claim Attributes: TODO" << std::endl;

		free(tokenDeviceClaimAttributes);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenRestrictedUserClaimAttributes(HANDLE token) {
	try {
		void* tokenRestrictedUserClaimAttributes = reinterpret_cast<void*>(GetTokenInfo(token, TokenRestrictedUserClaimAttributes));

		std::wcout << L"Token Restricted User Claim Attributes: TODO" << std::endl;

		free(tokenRestrictedUserClaimAttributes);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenRestrictedDeviceClaimAttributes(HANDLE token) {
	try {
		void* tokenRestrictedDeviceClaimAttributes = reinterpret_cast<void*>(GetTokenInfo(token, TokenRestrictedDeviceClaimAttributes));

		std::wcout << L"Token Restricted Device Claim Attributes: TODO" << std::endl;

		free(tokenRestrictedDeviceClaimAttributes);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenDeviceGroups(HANDLE token) {
	try {
		TOKEN_GROUPS* tokenDeviceGroups = reinterpret_cast<TOKEN_GROUPS*>(GetTokenInfo(token, TokenDeviceGroups));

		std::wcout << L"Token Device Groups [" << tokenDeviceGroups->GroupCount << L"]:"; if (tokenDeviceGroups->GroupCount == 0) { std::wcout << L" None"; } std::wcout << std::endl;
		for (DWORD i = 0; i < tokenDeviceGroups->GroupCount; i++)
		{
			if (i != 0) { std::wcout << std::endl; }
			std::wcout << "    SID: "; FormatSID(tokenDeviceGroups->Groups[i].Sid); std::wcout << std::endl;
			std::wcout << "    Attributes: "; FormatBinary(reinterpret_cast<BYTE*>(&tokenDeviceGroups->Groups[i].Attributes), 4); std::wcout << std::endl;
		}

		free(tokenDeviceGroups);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenRestrictedDeviceGroups(HANDLE token) {
	try {
		std::wcout << L"Token Restricted Device Groups: TODO Seems to be broken at a system level." << std::endl;
		return;

		TOKEN_GROUPS* tokenRestrictedDeviceGroups = reinterpret_cast<TOKEN_GROUPS*>(GetTokenInfo(token, TokenRestrictedDeviceGroups));

		std::wcout << L"Token Restricted Device Groups (" << tokenRestrictedDeviceGroups->GroupCount << L"):" << std::endl;

		for (DWORD i = 0; i < tokenRestrictedDeviceGroups->GroupCount; i++)
		{
			if (i != 0) {
				std::wcout << std::endl;
			}

			std::wcout << "    SID: ";
			FormatSID(tokenRestrictedDeviceGroups->Groups[i].Sid);
			std::wcout << std::endl;

			std::wcout << "    Attributes: ";
			FormatBinary(reinterpret_cast<BYTE*>(&tokenRestrictedDeviceGroups->Groups[i].Attributes), 4);
			std::wcout << std::endl;
		}

		free(tokenRestrictedDeviceGroups);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenSecurityAttributes(HANDLE token) {
	try {
		void* tokenSecurityAttributes = reinterpret_cast<void*>(GetTokenInfo(token, TokenSecurityAttributes));

		std::wcout << L"Token Security Attributes: TODO" << std::endl;

		free(tokenSecurityAttributes);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenIsRestricted(HANDLE token) {
	try {
		void* tokenIsRestricted = reinterpret_cast<void*>(GetTokenInfo(token, TokenIsRestricted));

		std::wcout << L"Token Is Restricted: TODO" << std::endl;

		free(tokenIsRestricted);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenProcessTrustLevel(HANDLE token) {
	try {
		void* tokenProcessTrustLevel = reinterpret_cast<void*>(GetTokenInfo(token, TokenProcessTrustLevel));

		std::wcout << L"Token Process Trust Level: TODO" << std::endl;

		free(tokenProcessTrustLevel);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenPrivateNameSpace(HANDLE token) {
	try {
		void* tokenPrivateNameSpace = reinterpret_cast<void*>(GetTokenInfo(token, TokenPrivateNameSpace));

		std::wcout << L"Token Private Name Space: TODO" << std::endl;

		free(tokenPrivateNameSpace);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenSingletonAttributes(HANDLE token) {
	try {
		void* tokenSingletonAttributes = reinterpret_cast<void*>(GetTokenInfo(token, TokenSingletonAttributes));

		std::wcout << L"Token Singleton Attributes: TODO" << std::endl;

		free(tokenSingletonAttributes);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenBnoIsolation(HANDLE token) {
	try {
		void* tokenBnoIsolation = reinterpret_cast<void*>(GetTokenInfo(token, TokenBnoIsolation));

		std::wcout << L"Token BNO Isolation: TODO" << std::endl;

		free(tokenBnoIsolation);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenChildProcessFlags(HANDLE token) {
	try {
		void* tokenChildProcessFlags = reinterpret_cast<void*>(GetTokenInfo(token, TokenChildProcessFlags));

		std::wcout << L"Token Child Process Flags: TODO" << std::endl;

		free(tokenChildProcessFlags);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenIsLessPrivilegedAppContainer(HANDLE token) {
	try {
		void* tokenIsLessPrivilegedAppContainer = reinterpret_cast<void*>(GetTokenInfo(token, TokenIsLessPrivilegedAppContainer));

		std::wcout << L"Token Is Less Privileged App Container: TODO" << std::endl;

		free(tokenIsLessPrivilegedAppContainer);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenIsSandboxed(HANDLE token) {
	try {
		void* tokenIsSandboxed = reinterpret_cast<void*>(GetTokenInfo(token, TokenIsSandboxed));

		std::wcout << L"Token Is Sandboxed: TODO" << std::endl;

		free(tokenIsSandboxed);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenIsAppSilo(HANDLE token) {
	try {
		void* tokenIsAppSilo = reinterpret_cast<void*>(GetTokenInfo(token, TokenIsAppSilo));

		std::wcout << L"Token Is App Silo: TODO" << std::endl;

		free(tokenIsAppSilo);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}
void PrintTokenLoggingInformation(HANDLE token) {
	std::wcout << L"Token Logging Information: TODO (Not supported by SDK)" << std::endl;
	/*
	try {
		void* tokenLoggingInformation = reinterpret_cast<void*>(GetTokenInfo(token, TokenLoggingInformation));

		std::wcout << L"Token Logging Information: TODO" << std::endl;

		free(tokenLoggingInformation);
	}
	catch (Error error) { error.PrintAndFree(); return; }
	*/
}
void PrintMaxTokenInfoClass(HANDLE token) {
	try {
		void* maxTokenInfoClass = reinterpret_cast<void*>(GetTokenInfo(token, MaxTokenInfoClass));

		std::wcout << L"Max Token Info Class: TODO" << std::endl;

		free(maxTokenInfoClass);
	}
	catch (Error error) { error.PrintAndFree(); return; }
}

void PrintTokenInfo(HANDLE token) {
	PrintTokenHandle(token); std::wcout << std::endl;
	PrintTokenUser(token); std::wcout << std::endl;
	PrintTokenGroups(token); std::wcout << std::endl;
	PrintTokenPrivileges(token); std::wcout << std::endl;
	PrintTokenOwner(token); std::wcout << std::endl;
	PrintTokenPrimaryGroup(token); std::wcout << std::endl;
	PrintTokenDefaultDacl(token); std::wcout << std::endl;
	PrintTokenSource(token); std::wcout << std::endl;
	PrintTokenType(token); std::wcout << std::endl;
	PrintTokenImpersonationLevel(token); std::wcout << std::endl;
	PrintTokenStatistics(token); std::wcout << std::endl;
	PrintTokenRestrictedSids(token); std::wcout << std::endl;
	PrintTokenSessionID(token); std::wcout << std::endl;
	PrintTokenGroupsAndPrivileges(token); std::wcout << std::endl;
	PrintTokenSessionReference(token); std::wcout << std::endl;
	PrintTokenSandBoxInert(token); std::wcout << std::endl;
	PrintTokenAuditPolicy(token); std::wcout << std::endl;
	PrintTokenOrigin(token); std::wcout << std::endl;
	PrintTokenElevationType(token); std::wcout << std::endl;
	PrintTokenLinkedToken(token); std::wcout << std::endl;
	PrintTokenElevation(token); std::wcout << std::endl;
	PrintTokenHasRestrictions(token); std::wcout << std::endl;
	PrintTokenAccessInformation(token); std::wcout << std::endl;
	PrintTokenVirtualizationAllowed(token); std::wcout << std::endl;
	PrintTokenVirtualizationEnabled(token); std::wcout << std::endl;
	PrintTokenIntegrityLevel(token); std::wcout << std::endl;
	PrintTokenUIAccess(token); std::wcout << std::endl;
	PrintTokenMandatoryPolicy(token); std::wcout << std::endl;
	PrintTokenLogonSid(token); std::wcout << std::endl;
	PrintTokenIsAppContainer(token); std::wcout << std::endl;
	PrintTokenCapabilities(token); std::wcout << std::endl;
	PrintTokenAppContainerSid(token); std::wcout << std::endl;
	PrintTokenAppContainerNumber(token); std::wcout << std::endl;
	PrintTokenUserClaimAttributes(token); std::wcout << std::endl;
	PrintTokenDeviceClaimAttributes(token); std::wcout << std::endl;
	PrintTokenRestrictedUserClaimAttributes(token); std::wcout << std::endl;
	PrintTokenRestrictedDeviceClaimAttributes(token); std::wcout << std::endl;
	PrintTokenDeviceGroups(token); std::wcout << std::endl;
	PrintTokenRestrictedDeviceGroups(token); std::wcout << std::endl;
	PrintTokenSecurityAttributes(token); std::wcout << std::endl;
	PrintTokenIsRestricted(token); std::wcout << std::endl;
	PrintTokenProcessTrustLevel(token); std::wcout << std::endl;
	PrintTokenPrivateNameSpace(token); std::wcout << std::endl;
	PrintTokenSingletonAttributes(token); std::wcout << std::endl;
	PrintTokenBnoIsolation(token); std::wcout << std::endl;
	PrintTokenChildProcessFlags(token); std::wcout << std::endl;
	PrintTokenIsLessPrivilegedAppContainer(token); std::wcout << std::endl;
	PrintTokenIsSandboxed(token); std::wcout << std::endl;
	PrintTokenIsAppSilo(token); std::wcout << std::endl;
	PrintTokenLoggingInformation(token); std::wcout << std::endl;
	PrintMaxTokenInfoClass(token); std::wcout << std::endl;
}