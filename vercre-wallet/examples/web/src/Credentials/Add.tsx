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

export type AddProps = {
    onClose: () => void;
};

const Add = (props: AddProps) => {
    const { onClose } = props;
    const [offer, setOffer] = useState<string>("");
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
            title: 'Add Credential',
            action: (
                <IconButton onClick={onClose} size="large">
                    <ArrowBackIosIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                </IconButton>
            ),
            secondaryAction: undefined,
        });
    }, [onClose, setShellState, theme.palette.primary.contrastText]);

    const handleChange = (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
        const val = e.target.value.trim();
        setOffer(val);
        if (val === "") {
            setError("Offer is required");
        }
    };

    const handleSubmit = () => {
        if (offer === "") {
            return;
        }
        const encoded = encodeURIComponent(offer);
        update(new st.EventVariantIssuance(new st.IssuanceEventVariantOffer(encoded)));
    };

    return (
        <Stack>
            <Typography gutterBottom>
                Paste the Verifiable Credential offer.
            </Typography>
            <Alert severity="info">You will have a chance to review the Credential before it is added</Alert>
            <TextField
                error={!!error}
                fullWidth
                helperText={error}
                inputProps={{ maxLength: 1024 }}
                label="Offer"
                margin="normal"
                multiline
                name="offer"
                onChange={handleChange}
                required
                rows={10}
                size="small"
                value={offer}
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
                    disabled={!!error || offer === ""}
                    onClick={handleSubmit}
                    variant="contained"
                >
                    Review
                </Button>
            </Box>
        </Stack>
    );
};

export default Add;
