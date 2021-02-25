/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import base64url from 'base64url-universal';

const SEED_CACHE_KEY = 'webkms-seed-cache';

export class SeedCache {
  constructor() {
    if(typeof window !== 'undefined' &&
      typeof window.localStorage !== 'undefined') {
      this.storage = window.localStorage;
    }
  }

  async set(key, value) {
    if(!this.storage) {
      return false;
    }

    const cache = this._getCache();

    try {
      cache[key] = base64url.encode(value);
      return this._updateCache(cache);
    } catch(e) {}

    return false;
  }

  async get(key) {
    if(!this.storage) {
      return false;
    }

    const cache = this._getCache();

    try {
      const encodedSeed = cache[key];
      if(encodedSeed) {
        return base64url.decode(encodedSeed);
      }
    } catch(e) {}

    return null;
  }

  async delete(key) {
    if(!this.storage) {
      return false;
    }

    const cache = this._getCache();

    try {
      delete cache[key];
      return this._updateCache(cache);
    } catch(e) {}

    return false;
  }

  _updateCache(cache) {
    try {
      this.storage.setItem(SEED_CACHE_KEY, JSON.stringify(cache));
      return true;
    } catch(e) {}
    return false;
  }

  _getCache() {
    let cache;
    try {
      cache = JSON.parse(this.storage.getItem(SEED_CACHE_KEY)) || {};
    } catch(e) {
      cache = {};
    }
    return cache;
  }
}
