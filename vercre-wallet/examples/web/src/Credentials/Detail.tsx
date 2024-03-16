import { useEffect, useRef, useState } from 'react';

import ArrowBackIosIcon from '@mui/icons-material/ArrowBackIos';
import DeleteForeverIcon from "@mui/icons-material/DeleteForever";
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import Typography from '@mui/material/Typography';
import { Optional } from 'shared_types/serde/types';
import * as st from "shared_types/types/shared_types";

import { dateFromIso, domainFromUrl } from '.';
import Delete from './Delete';
import VcCard, { VcCardProps } from "./VcCard";
import { useShellState } from '../Shell/Context';
import { useViewState } from '../ViewState';

export type DetailProps = {
    credential: st.Credential;
    onClose: () => void;
};

const Detail = (props: DetailProps) => {
    const { credential, onClose } = props;
    const [confirmDelete, setConfirmDelete] = useState<boolean>(false);
    const { setShellState } = useShellState();
    const { update } = useViewState();
    const initialLoad = useRef<boolean>(true);
    const theme = useTheme();

    const claimValues = credential.vc.credentialSubject;
    const display = credential.metadata.display?.at(0);

    useEffect(() => {
        if (!initialLoad.current) {
            return;
        }
        initialLoad.current = false;
        setShellState({
            title: credential.metadata.display?.at(0)?.name || "Credential Detail",
            action: (
                <IconButton onClick={onClose} size="large">
                    <ArrowBackIosIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                </IconButton>
            ),
            secondaryAction: (
                <IconButton onClick={() => setConfirmDelete(true)} size="large">
                    <DeleteForeverIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                </IconButton>
            ),
        })
    }, [credential.metadata.display, onClose, setShellState, theme.palette.primary.contrastText]);

    const handleDelete = (id?: string) => {
        setConfirmDelete(false);
        if (!id) {
            return;
        }
        update(new st.EventVariantCredential(new st.CredentialEventVariantDelete(id)));
        onClose();
    };

    const displayProps = (): VcCardProps => {
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

    const claimNames = credential.metadata.credential_definition.credentialSubject;
    const claimName = (key: string): string => {
        if (claimNames) {
            const locale = navigator.language;  // TODO: use user's preferred language (settings)
            for (const [k, v] of Object.entries(claimNames)) {
                if (k === key && v.display) {
                    for (const d of v.display) {
                        if (d.locale === locale) {
                            return d.name;
                        }
                    }
                }
            }
        }
        return key;
    };

    return (<>
        <Stack spacing={2} sx={{ pt: 2 }}>
            <VcCard { ...displayProps() } />
            <Typography variant="h5">
                Verified Info
            </Typography>
            <ClaimEntry name="Description" value={display?.description} />
            {claimValues && Object.entries(claimValues).map(([key, value]) => (
                <ClaimEntry key={key} name={claimName(key)} value={value} />
            ))}
            <ClaimEntry name="Issued on" value={dateFromIso(credential.vc.issuanceDate)} />
            <ClaimEntry name="Expires on" value={
                credential.vc.expirationDate ? dateFromIso(credential.vc.expirationDate) : 'Never'
            } />
            <ClaimEntry name="Issued by" value={domainFromUrl(credential.issuer)} />
        </Stack>
        <Delete
            name={displayProps().name || 'Credential'}
            open={confirmDelete}
            onClose={() => setConfirmDelete(false)}
            onDelete={() => handleDelete(credential.id)}
        />
    </>);
}

export default Detail;

const ClaimEntry = (props: { name: string, value: Optional<string> | undefined }) => {
    return (<>
        {props.name === 'id' ? null :
            <Box>
                <Typography variant="caption">
                    {props.name}
                </Typography>
                <Typography variant="body1">
                    {props.value}
                </Typography>
            </Box>
        }
    </>);
};
