/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.tag.model.json;

import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.JsonDeserializer;
import org.codehaus.jackson.JsonNode;
import com.intel.mtwilson.datatypes.X509AttributeCertificate;
import java.io.IOException;

/**
 *
 * @author rksavino
 */
public class X509AttributeCertificateDeserializer extends JsonDeserializer<X509AttributeCertificate> {

    @Override
    public X509AttributeCertificate deserialize(JsonParser jp, DeserializationContext dc) throws IOException, JsonProcessingException {
        JsonNode node = jp.getCodec().readTree(jp);
        byte[] encodedBytes = node.get("encoded").getBinaryValue();
        return X509AttributeCertificate.valueOf(encodedBytes);
    }
    
}
