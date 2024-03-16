import { useEffect, useRef } from "react";

import ArrowBackIosIcon from '@mui/icons-material/ArrowBackIos';
import Alert from '@mui/material/Alert';
import IconButton from '@mui/material/IconButton';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import * as st from 'shared_types/types/shared_types';

import { useShellState } from '../Shell/Context';
import { useViewState } from '../ViewState';

export type ErrorProps = {
    title: string,
    message: string,
};

const Error = (props: ErrorProps) => {
    const { setShellState } = useShellState();
    const { update } = useViewState();
    const initialLoad = useRef<boolean>(true);
    const theme = useTheme();

    useEffect(() => {
        if (!initialLoad.current) {
            return;
        }
        initialLoad.current = false;
        setShellState({
            title: props.title,
            action: (
                <IconButton onClick={() => update(new st.EventVariantCancel())} size="large">
                    <ArrowBackIosIcon
                        fontSize="large"
                        sx={{ color: theme.palette.primary.contrastText}}
                    />
                </IconButton>
            ),
            secondaryAction: undefined,
        });
    }, [props.title, setShellState, theme.palette.primary.contrastText]);
    
    return (
        <Stack spacing={2} sx={{ my: 2 }}>
            <Alert severity="error">
                {props.message}
            </Alert>
        </Stack>
    );
};

export default Error;
