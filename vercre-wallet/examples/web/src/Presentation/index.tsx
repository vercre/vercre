import { useEffect, useRef, useState } from 'react';

import Box from '@mui/material/Box';
import * as st from "shared_types/types/shared_types";

import Authorize from './Authorize';
import Error from '../components/Error';
import RequestStatus from '../components/RequestStatus';
import { useShellState } from '../Shell/Context';
import { useViewState } from '../ViewState';

export const Presentation = () => {
    const [mode, setMode] = useState<'authorize' | 'request' | 'error'>('authorize');
    const { setShellState } = useShellState();
    const { viewModel } = useViewState();
    const initialLoad = useRef<boolean>(true);

    const model = viewModel.presentation;

    // set the default shell state
    useEffect(() => {
        if (!initialLoad.current) {
            return;
        }
        initialLoad.current = false;
        setShellState({
            title: 'Accept Credential',
            action: undefined,
            secondaryAction: undefined,
        });
    }, [setShellState]);
    

    // translate status to mode
    useEffect(() => {
        const status = Object(model.status);
        if (Object.prototype.hasOwnProperty.call(status, 'Failed')) {
            setMode('error');
            return;
        }
        switch (String(model.status)) {
            case "Authorized":
            case "Completed":
                setMode('request');
                break;
            default:
                setMode('authorize');
                break;
        }
    }, [model]);

    return (
        <Box sx={{ pt: 1, position: 'relative'}}>
            { mode === 'authorize' &&
                <Authorize />
            }
            { mode === 'request' &&
                <RequestStatus
                    title="Verifying credentials..."
                    status={
                        model.status.constructor === st.PresentationStatusVariantRequested
                        ? 'pending'
                        : 'complete'
                    }
                />
            }
            { mode === 'error' &&
                <Error
                    title="Present Credential"
                    message="An error occurred. Please try again or contact the verifier."
                />
            }
        </Box>
    );
}

export default Presentation;
