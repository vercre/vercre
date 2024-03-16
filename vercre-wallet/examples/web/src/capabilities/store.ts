// IMPORTANT! This example is for demonstration purposes only. Do not use browser local storage to
// store credentials in production. A secure remote service should be used which implies an
// authentication layer in the wallet which is not implemented in this simple example.

import * as st from 'shared_types/types/shared_types';
import { Seq, uint8 } from 'shared_types/serde/types';

export const store = async (request: st.StoreRequest): Promise<st.StoreResponse> => {
    console.log('store', request);

    switch (request.constructor) {
        case st.StoreRequestVariantAdd: {
            const addRequest = request as st.StoreRequestVariantAdd;
            return add(addRequest.field0, addRequest.field1);
        }
        case st.StoreRequestVariantDelete: {
            const deleteRequest = request as st.StoreRequestVariantDelete;
            return remove(deleteRequest.value);
        }
        case st.StoreRequestVariantList: {
            return list();
        }
        default: {
            return new st.StoreResponseVariantErr('invalid request');
        }
    }
};

const add = async (id: string, value: Seq<uint8>): Promise<st.StoreResponse> => {
    console.log('store add', id, value);

    // HACK: Store the bytes in local storage. For production call a store API.
    try {
        window.localStorage.setItem(id, JSON.stringify(value));
        return new st.StoreResponseVariantOk();
    } catch (err) {
        console.error('store add', err);
        return new st.StoreResponseVariantErr('failed to store');
    }
}

const remove = async (id: string): Promise<st.StoreResponse> => {
    console.log('store remove', id);

    // HACK: Delete the bytes from local storage. For production call a store API.
    try {
        window.localStorage.removeItem(id);
        return new st.StoreResponseVariantOk();
    } catch (err) {
        console.error('store remove', err);
        return new st.StoreResponseVariantErr('failed to remove');
    }
}

const list = async (): Promise<st.StoreResponse> => {
    console.log('store list');

    // HACK: Get all the things from local storage. For production call a store API.
    try {
        let entries: st.StoreEntry[] = [];
        const keys = Object.keys(window.localStorage);
        for (let i = 0; i < keys.length; i++) {
            const key = keys[i];
            const value = window.localStorage.getItem(key);
            if (value === null) {
                continue;
            }
            entries.push(new st.StoreEntry(JSON.parse(value)));
        }
        return new st.StoreResponseVariantList(entries);
    } catch (err) {
        console.error('store list', err);
        return new st.StoreResponseVariantErr('failed to list');
    }
};

