import { useState } from "react";

import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import { useTheme } from '@mui/material/styles';
import Typography from '@mui/material/Typography';
import * as st from "shared_types/types/shared_types";
import tinycolor from 'tinycolor2';

import { domainFromUrl } from ".";

export type VcCardProps = {
    backgroundColor?: string;
    color?: string;
    issuer?: string;
    logo?: st.EncodedLogo;
    logoUrl?: string;
    name?: string;
    onSelect?: (selected: boolean) => void;
};

const cardWidth = 300;
const ratio = 1.59;

export const VcCard = (props: VcCardProps) => {
    const {
        backgroundColor,
        color,
        issuer,
        logo,
        logoUrl,
        name,
        onSelect,
    } = props;
    const [selected, setSelected] = useState(false);
    const theme = useTheme();

    const handleSelect = () => {
        setSelected(!selected);
        onSelect && onSelect(!selected);
    };

    const bg = backgroundColor || theme.palette.primary.main;
    const shadeColor = tinycolor(bg).brighten(33).toString();

    return (
        <Card
            elevation={4}
            sx={{
                background: `linear-gradient(135deg, ${bg} 30%, ${shadeColor})`,
                color: color || theme.palette.primary.contrastText,
                cursor: 'pointer',
                height: cardWidth / ratio,
                width: cardWidth,
            }}
            onClick={handleSelect}
        >
            <CardContent
                sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    height: '100%',
                    pt: 0,
                }}>
                <CardHeader issuer={issuer} logo={logo} logoUrl={logoUrl} name={name} />
                <Box sx={{ flexGrow: 2 }}>&nbsp;</Box>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Typography component="div" variant="body2" sx={{ flexGrow: 1 }}>
                        {domainFromUrl(issuer)}
                    </Typography>
                    <Box>
                    {selected === true &&
                        <CheckCircleOutlineIcon />
                    }
                    </Box>
                </Box>
            </CardContent>
        </Card>
    );
}

type CardHeaderProps = {
    issuer?: string;
    logo?: st.EncodedLogo;
    logoUrl?: string;
    name?: string;
}

const CardHeader = (props: CardHeaderProps) => {
    const { issuer, logo, logoUrl, name } = props;
    return (
        <Box sx={{ display: 'flex', alignItems: 'flex-start', flexGrow: 1, pt: 2 }}>
            <Box sx={{ height: 36, maxWidth: '50%' }}>
                {logo    
                    ? <img
                        src={`data:${logo.media_type};charset=utf-8;base64, ${logo.image}`}
                        alt={issuer}
                        style={{ maxHeight: '100%', maxWidth: '100%' }}
                    />
                    : <>
                        {logoUrl
                            ? <img
                                src={logoUrl}
                                alt={issuer}
                                style={{ maxHeight: '100%', maxWidth: '100%' }}
                                />
                            : <FingerprintIcon />
                        }
                    </>
                }
            </Box>
            <Box sx={{ textAlign: 'right', flexGrow: 1, mt: '-2px' }}>
                <Typography component="span">
                    {name}
                </Typography>
            </Box>
        </Box>
    );
};

export default VcCard;