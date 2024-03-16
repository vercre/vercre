import { createContext, ReactNode, useContext, useReducer } from 'react';

import * as bin from 'shared_types/bincode/mod';
import * as st from 'shared_types/types/shared_types';
import { handle_response, process_event, view } from 'vercre-wallet/vercre_wallet';

import { request as http } from './capabilities/http';
import { store } from './capabilities/store';

type Response = st.HttpResponse | st.StoreResponse;

const initView = (): st.ViewModel => {
    return new st.ViewModel(
        new st.CredentialView([]),
        new st.IssuanceView('', new Map<string, st.CredentialConfiguration>(), new st.IssuanceStatusVariantInactive()),
        new st.PresentationView([], new st.PresentationStatusVariantInactive()),
        null,
        new st.ViewVariantSplash(),
    );
};

export type ViewState = {
    viewModel: st.ViewModel,
};

export type Action = {
    type: 'set',
    payload: st.ViewModel,
};

type Dispatch = (action: Action) => void;

export const ViewContext = createContext<{ state: ViewState; dispatch: Dispatch} | undefined>(undefined);

const reducer = (_state: ViewState, action: Action): ViewState => {
    return { viewModel: action.payload };
};

export type ViewProviderProps = {
    children: ReactNode,
};

export const ViewStateProvider = (props: ViewProviderProps) => {
    const { children } = props;
    const [state, dispatch] = useReducer(reducer, { viewModel: initView() });
    const value = { state, dispatch };

    return (
        <ViewContext.Provider value={value}>
            {children}
        </ViewContext.Provider>
    );
};

export const useViewState = () => {
    const context = useContext(ViewContext);
    if (!context) {
        throw new Error('useViewState must be used within a ViewStateProvider');
    }
    const { dispatch } = context;

    const deserializeRequests = (bytes: Uint8Array): st.Request[] => {
        const deserializer = new bin.BincodeDeserializer(bytes);
        const len = deserializer.deserializeLen();
        const requests: st.Request[] = [];
        for (let i = 0; i < len; i++) {
            requests.push(st.Request.deserialize(deserializer));
        }
        return requests;
    };
    
    const deserializeView = (bytes: Uint8Array): st.ViewModel => {
        console.log("attempt to deserialize view", Array.from(bytes));
        const vm = st.ViewModel.deserialize(new bin.BincodeDeserializer(bytes));
        console.log("deserialised:", vm);
        return vm;
    };    

    const respond = (
        uuid: number[],
        response: Response,
        dispatch: Dispatch): void => {
        const serializer = new bin.BincodeSerializer();
        response.serialize(serializer);
    
        const effects = handle_response(new Uint8Array(uuid), serializer.getBytes());
    
        const requests = deserializeRequests(effects);
        for (const request of requests) {
            processEffect(request.uuid, request.effect, dispatch);
        }
    };    

    const processEffect = async (
        uuid: number[],
        effect: st.Effect,
        dispatch: Dispatch): Promise<void> => {
        console.log('processEffect', effect);
    
        switch (effect.constructor) {
            case st.EffectVariantRender: {
                dispatch({ type: 'set', payload: deserializeView(view())});
                break;
            }
            case st.EffectVariantHttp: {
                const request = (effect as st.EffectVariantHttp).value;
                const response = await http(request);
                respond(uuid, response, dispatch);
                break;
            }
            case st.EffectVariantStore: {
                const request = (effect as st.EffectVariantStore).value;
                const response = await store(request);
                respond(uuid, response, dispatch);
                break;
            }
        }
    };

    const update = (event: st.Event) => {
        console.log('update', event);

        const serializer = new bin.BincodeSerializer();
        event.serialize(serializer);

        const effects = process_event(serializer.getBytes());

        const requests = deserializeRequests(effects);
        for (const request of requests) {
            processEffect(request.uuid, request.effect, dispatch);
        }
    };

    return {
        viewModel: context.state.viewModel,
        update,
    };
};
