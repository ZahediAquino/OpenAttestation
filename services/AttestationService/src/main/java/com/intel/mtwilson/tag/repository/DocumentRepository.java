/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.tag.repository;

import com.intel.mtwilson.tag.repository.AbstractDocument;
import com.intel.mtwilson.datatypes.SearchableRepository;
import com.intel.mtwilson.tag.repository.DocumentCollection;
import com.intel.mtwilson.datatypes.FilterCriteria;
import com.intel.mtwilson.datatypes.Locator;
import com.intel.mtwilson.datatypes.SearchableRepository;

/**
 * 
 * @author jbuhacoff
 */
//public interface SimpleRepository<T extends Document, C extends DocumentCollection<T>, F extends FilterCriteria<T>, L extends Locator<T>> {
public interface DocumentRepository<T extends AbstractDocument, C extends DocumentCollection<T>, F extends FilterCriteria<T>, L extends Locator<T>> extends SearchableRepository<T,L,C,F> {


}
