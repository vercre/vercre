import { useEffect, useMemo, useRef, useState } from "react";

import AddIcon from '@mui/icons-material/Add';
import BadgeIcon from '@mui/icons-material/BadgeOutlined';
import Box from '@mui/material/Box';
import Fab from '@mui/material/Fab';
import IconButton from '@mui/material/IconButton';
import Slide from '@mui/material/Slide';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import * as st from 'shared_types/types/shared_types';

import Add from './Add';
import Detail from './Detail';
import Present from './Present';
import VcCard, { VcCardProps } from './VcCard';
import { useShellState } from '../Shell/Context';
import { useViewState } from "../ViewState";

const Credentials = () => {
    const [selected, setSelected] = useState<st.Credential | undefined>(undefined);
    const [viewMode, setViewMode] = useState<'list' | 'detail' | 'add' | 'present'>('list');
    const { setShellState } = useShellState();
    const { viewModel, update } = useViewState();
    const initialLoad = useRef<boolean>(true);
    const theme = useTheme();

    const credentials = viewModel.credential.credentials;
    console.debug(credentials);

    const listShellState = useMemo(() => ({
        title: 'Credentials',
        action: undefined,
        secondaryAction: (
            <IconButton onClick={() => setViewMode('present')} size="large">
                <BadgeIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
            </IconButton>
        ),
    }), [theme.palette.primary.contrastText]);

    // On initial load of this component, get the list of credentials from the store capability by
    // invoking the crux event.
    useEffect(() => {
        if (!initialLoad.current) {
            return;
        }
        initialLoad.current = false;
        setShellState({...listShellState});
        update(new st.EventVariantCredential(new st.CredentialEventVariantList));
    }, []);

    // If the user clicks on a credential card, show the detail view of that credential.
    const handleSelect = (c: st.Credential) => {
        setSelected(c);
        setViewMode('detail');
    };

    // If the user closes a specific view, go back to the list view.
    const handleClose = () => {
        setSelected(undefined);
        setViewMode('list');
        setShellState({...listShellState});
    };

    // If the user clicks on the add button, show the add view.
    const handleAdd = () => {
        setSelected(undefined);
        setViewMode('add');
    };

    // Determine the props to display for a specific credential card.
    const displayProps = (credential: st.Credential) : VcCardProps => {
        const locale = navigator.language; // TODO: use user preference from settings
        const display = credential.metadata.display?.find(d => d.locale === locale);
        return {
            backgroundColor: display?.background_color || undefined,
            color: display?.text_color || undefined,
            issuer: credential.issuer,
            logo: credential.logo || undefined,
            logoUrl: undefined,
            name: display?.name || 'Credential',
            onSelect: () => handleSelect(credential),            
        };
    };

    return(
        <Box
            sx={{
                pt: 1,
                position: 'relative',
            }}
        >
            <Slide direction="right" in={viewMode === 'list'} mountOnEnter unmountOnExit>
                <Stack
                    spacing={-16}
                    sx={{
                        position: 'absolute',
                        top: 0,
                        pt: 2,
                    }}
                >
                    {credentials?.map((c, i) =>
                        <Stack key={i} spacing={-2} sx={{ pt: 2 }}>
                            <VcCard {...displayProps(c)} />
                        </Stack>
                    )}
                    <Fab
                        color="primary"
                        onClick={handleAdd}
                        sx={{ position: 'fixed', bottom: 56, right: 24 }}
                    >
                        <AddIcon />
                    </Fab>
                </Stack>
            </Slide>
            <StackItem view={viewMode === 'detail'}>
                {selected && <Detail credential={selected} onClose={handleClose} />}
            </StackItem>
            <StackItem view={viewMode === 'add'}>
                <Add onClose={handleClose} />
            </StackItem>
            <StackItem view={viewMode === 'present'}>
                <Present onClose={handleClose} />
            </StackItem>
        </Box>
    );
};

export default Credentials;

type StackItemProps = {
    view: boolean;
    children: React.ReactNode;
};

const StackItem = (props: StackItemProps) => {
    return (
        <Slide direction="left" in={props.view} mountOnEnter unmountOnExit>
            <Box
                sx={{
                    position: 'absolute',
                    top: 0,
                    pt: 2,
                }}
            >
                {props.children}
            </Box>
        </Slide>
    );
};

export const domainFromUrl = (url: string | undefined): string => {
    if (!url) {
        return '';
    }
    const match = url.match(/:\/\/(.[^/]+)/);
    return match ? match[1] : url;
};

export const dateFromIso = (iso: string | undefined): string => {
    if (!iso) {
        return '';
    }
    const date = new Date(iso);
    return date.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });
};

