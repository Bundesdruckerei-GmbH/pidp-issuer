/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package COSE

import com.upokecenter.cbor.CBORObject
import de.bdr.pidp.issuer.issuance.core.signer.CredentialSigner

fun Sign1Message.sign(signer: CredentialSigner) {
    if (rgbContent == null) throw CoseException("No Content Specified")
    if (rgbSignature != null) return

    if (rgbProtected == null) {
        rgbProtected = if (objProtected.size() > 0) objProtected.EncodeToBytes() else ByteArray(0)
    }

    val obj = CBORObject.NewArray()
    obj.Add(contextString)
    obj.Add(rgbProtected)
    obj.Add(externalData)
    obj.Add(rgbContent)

    rgbSignature = signer.sign(obj.EncodeToBytes())

    ProcessCounterSignatures()
}
