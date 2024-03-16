/* Note: Only use this context for visual state management, not for application model state.
*  All model state should be managed in the Crux layer.
*/

import { createContext, JSX, ReactNode, useCallback, useContext, useReducer } from 'react';

export type ShellState = {
    title?: string,
    action?: JSX.Element,
    secondaryAction?: JSX.Element,
};

export type Action = {
    type: 'set',
    payload: ShellState,
};

type Dispatch = (action: Action) => void;

export type ShellStateProviderProps = {
    children: ReactNode,
};

const ShellStateContext = createContext<{state: ShellState; dispatch: Dispatch} | undefined>(undefined);

const reducer = (state: ShellState, action: Action): ShellState => {
    switch (action.type) {
        case 'set':
            return {
                ...state,
                ...action.payload
            };
        default:
            return state;
    }
};

export const ShellStateProvider = (props: ShellStateProviderProps) => {
    const { children } = props;
    const [state, dispatch] = useReducer(reducer, {});
    const value = { state, dispatch };

    return (
        <ShellStateContext.Provider value={value}>
            {children}
        </ShellStateContext.Provider>
    );
};

export const useShellState = () => {
    const context = useContext(ShellStateContext);
    if (context === undefined) {
        throw new Error('useShellState must be used within a ShellStateProvider');
    }

    const setShellState = useCallback((shellState: ShellState) => {
        context.dispatch({ type: 'set', payload: shellState });
    }, [context]);

    return {
        shellState: context.state,
        setShellState,
    };
};
