import { ReactNode } from "react";

import { Box } from "@mui/material";
import Container from "@mui/material/Container";
import Stack from "@mui/material/Stack";
import Toolbar from '@mui/material/Toolbar';

import Footer from './Footer';
import Header from './Header';

export type ShellProps = {
    children?: ReactNode;
};

const Shell = (props: ShellProps) => {
    return (
        <Stack
            sx = {{
                flexGrow: 1,
                minHeight: '100vh',
            }}            
        >
        <Header />
        <Container maxWidth="sm">
            <Box
                sx = {{
                    flexGrow: 1
                }}
            >
                <Toolbar/>
                {props.children}
            </Box>
        </Container>
        <Footer />
        </Stack>
    );
};

export default Shell;
