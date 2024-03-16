import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import * as st from 'shared_types/types/shared_types';

import VcCard, { VcCardProps } from '../Credentials/VcCard';
import { useViewState } from '../ViewState';

export const Accept = () => {
    const { viewModel, update } = useViewState();

    const model= viewModel.issuance;

    const displayProps = (credential: st.CredentialConfiguration) : VcCardProps => {
        const display = credential.display?.at(0);
        return {
            backgroundColor: display?.background_color || undefined,
            color: display?.text_color || undefined,
            issuer: model.issuer,
            logo: undefined,
            logoUrl: display?.logo?.uri || undefined,
            name: display?.name,
            onSelect: undefined,
        };
    };

    return (
        <Stack spacing={2} sx={{ pt: 2 }}>
            <Typography sx={{ pb: 1, textAlign: 'center' }}>
                Do you accept the following credentials?
            </Typography>
            {Object.entries(model?.offered).map(([key, supported]) => (
                <Box key={key} sx={{ display: 'flex', justifyContent: 'center'}}>
                    <VcCard { ...displayProps(supported) } />
                </Box>
            ))}
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
                    onClick={() => update(new st.EventVariantIssuance(new st.IssuanceEventVariantAccept()))}
                    variant="contained"
                >
                    Accept
                </Button>
            </Box>
        </Stack>
    );
}

export default Accept;
