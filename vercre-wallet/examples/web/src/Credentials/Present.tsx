import { ChangeEvent, useEffect, useRef, useState } from 'react';

import ArrowBackIosIcon from '@mui/icons-material/ArrowBackIos';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import * as st from 'shared_types/types/shared_types';

import { useShellState } from '../Shell/Context';
import { useViewState } from "../ViewState";

export type PresentProps = {
    onClose: () => void;
};

const Present = (props: PresentProps) => {
    const { onClose } = props;
    const [request, setRequest] = useState<string>('');
    const [error, setError] = useState<string | undefined>(undefined);
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
            title: 'Present Credential',
            action: (
                <IconButton onClick={onClose} size="large">
                    <ArrowBackIosIcon
                        fontSize="large"
                        sx={{ color: theme.palette.primary.contrastText}}
                    />
                </IconButton>
            ),
            secondaryAction: undefined,
        });
    }, [onClose, setShellState, theme.palette.primary.contrastText]);

    const handleChange = (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
        const val = e.target.value.trim();
        setRequest(val);
        if (val === '') {
            setError('Request is required');
        }
    };

    const handleSubmit = () => {
        if (request === '') {
            return;
        }
        const encoded = encodeURIComponent(request);
        update(new st.EventVariantPresentation(new st.PresentationEventVariantRequested(encoded)));
    };

    return (
        <Stack>
            <Typography gutterBottom>
                Paste the presentation request URL.
            </Typography>
            <Alert severity="info">
                You will have a chance to authorize the presentation before it is sent
            </Alert>
            <TextField
                error={!!error}
                fullWidth
                helperText={error}
                inputProps={{ maxLength: 1024 }}
                label="Presentation request URL"
                margin="normal"
                name="request"
                onChange={handleChange}
                required
                size="small"
                value={request}
                variant="outlined"
            />
            <Box
                sx={{
                    display: 'flex',
                    my: 2,
                    justifyContent: 'center',
                }}
            >
                <Button
                    color="primary"
                    disabled={!!error || request === ""}
                    onClick={handleSubmit}
                    variant="contained"
                >
                    Present
                </Button>
            </Box>
        </Stack>
    );
};

export default Present;
