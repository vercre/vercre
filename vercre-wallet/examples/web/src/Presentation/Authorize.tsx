import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import * as st from 'shared_types/types/shared_types';

import VcCard, { VcCardProps } from '../Credentials/VcCard';
import { useViewState } from '../ViewState';

export const Authorize = () => {
    const { viewModel, update } = useViewState();
    const model = viewModel.presentation;

    const displayProps = (credential: st.Credential) : VcCardProps => {
        const display = credential.metadata.display?.at(0);
        return {
            backgroundColor: display?.background_color || undefined,
            color: display?.text_color || undefined,
            issuer: credential.issuer,
            logo: credential.logo || undefined,
            logoUrl: undefined,
            name: display?.name,
            onSelect: undefined,
        }
    };

    return (
        <Stack spacing={2} sx={{ pt: 2 }}>
            <Typography sx={{ pb: 1, textAlign: 'center' }}>
                Do you authorize presentation of the following credentials?
            </Typography>
            {model?.credentials.map((credential, index) =>
                <Box key={index} sx={{ display: 'flex', justifyContent: 'center' }}>
                    <VcCard { ...displayProps(credential) } />
                </Box>
            )}
            <Box
                sx={{
                    display: 'flex',
                    my: 2,
                    justifyContent: 'center',
                    gap: 4
                }}
            >
                <Button
                    onClick={() => update(new st.EventVariantCancel())}
                    variant="outlined"
                >
                    Cancel
                </Button>
                <Button
                    onClick={() => update(new st.EventVariantPresentation(new st.PresentationEventVariantAuthorized()))}
                    variant="contained"
                >
                    Authorize
                </Button>
            </Box>
        </Stack>
    );
}

export default Authorize;
